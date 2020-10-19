package ibmcloudsecrets

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"time"
)

// pathsRoles returns the path configurations for the CRUD operations on roles
func pathsRoles(b *ibmCloudSecretBackend) []*framework.Path {
	p := []*framework.Path{
		{
			Pattern: "roles/?",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
				},
			},
			HelpSynopsis:    strings.TrimSpace(roleListHelpSyn),
			HelpDescription: strings.TrimSpace(roleListHelpDesc),
		},
		{
			Pattern: "roles/" + framework.GenericNameRegex(nameField),
			Fields: map[string]*framework.FieldSchema{
				nameField: {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				accessGroupIDsField: {
					Type:        framework.TypeCommaStringSlice,
					Description: `Comma-separated list of IAM Access Group ids that the generated service ID will be added to.`,
				},
				serviceIDField: {
					Type:        framework.TypeString,
					Description: `A service ID to generate API keys for.`,
				},
				ttlField: {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				maxTTLField: {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lifetime of generated credentials. If not set or set to 0, will use system default.",
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck(nameField),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},

			HelpSynopsis:    strings.TrimSpace(roleHelpSyn),
			HelpDescription: strings.TrimSpace(roleHelpDesc),
		},
	}
	return p
}

type ibmCloudRole struct {
	AccessGroupIDs []string      `json:"access_group_ids"`
	ServiceID      string        `json:"service_id"`
	TTL            time.Duration `json:"ttl"`
	MaxTTL         time.Duration `json:"max_ttl"`
	BindingHash    string        `json:"binding_hash"`
}

func getStringHash(bindingsRaw string) string {
	ssum := sha256.Sum256([]byte(bindingsRaw)[:])
	return base64.StdEncoding.EncodeToString(ssum[:])
}

// role takes a storage backend and the name and returns the role's storage
// entry
func getRole(ctx context.Context, s logical.Storage, name string) (*ibmCloudRole, error) {
	raw, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := new(ibmCloudRole)
	if err := json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}

	return role, nil
}

// pathRoleExistenceCheck returns whether the role with the given name exists or not.
func (b *ibmCloudSecretBackend) pathRoleExistenceCheck(rolesetFieldName string) framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
		role, err := getRole(ctx, req.Storage, d.Get(rolesetFieldName).(string))
		if err != nil {
			return false, err
		}
		return role != nil, nil
	}
}

// pathRoleList is used to list all the Roles registered with the backend.
func (b *ibmCloudSecretBackend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, rolesStoragePath+"/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

// pathRoleRead grabs a read lock and reads the options set on the role from the storage
func (b *ibmCloudSecretBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(nameField).(string)
	if roleName == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	d := map[string]interface{}{
		accessGroupIDsField: role.AccessGroupIDs,
		serviceIDField:      role.ServiceID,
		ttlField:            role.TTL / time.Second,
		maxTTLField:         role.MaxTTL / time.Second,
	}
	return &logical.Response{
		Data: d,
	}, nil
}

// pathRoleDelete removes the role from storage
func (b *ibmCloudSecretBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get(nameField).(string)
	if roleName == "" {
		return logical.ErrorResponse("role name required"), nil
	}

	// Delete the role itself
	if err := req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, roleName)); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleCreateUpdate registers a new role with the backend or updates the options
// of an existing role
func (b *ibmCloudSecretBackend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, resp := b.getConfig(ctx, req.Storage)
	if resp != nil {
		return resp, nil
	}

	roleName := d.Get(nameField).(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	// Check if the role already exists
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	// Create a new entry object if this is a CreateOperation
	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("role entry not found during update operation")
		}
		role = new(ibmCloudRole)
	}
	accessGroups, ok := d.GetOk(accessGroupIDsField)
	if ok {
		role.AccessGroupIDs = accessGroups.([]string)
		role.BindingHash = getStringHash(fmt.Sprintf("%s", role.AccessGroupIDs))
	}

	serviceID, ok := d.GetOk(serviceIDField)
	if ok {
		role.ServiceID = serviceID.(string)
		role.BindingHash = getStringHash(role.ServiceID)
	}

	if len(role.AccessGroupIDs) == 0 && len(role.ServiceID) == 0 {
		return logical.ErrorResponse("either a service ID or a non empty access group list are required"), nil
	}

	if len(role.AccessGroupIDs) != 0 && len(role.ServiceID) != 0 {
		if req.Operation == logical.UpdateOperation {
			return logical.ErrorResponse("to change the role binding between service IDs and access groups you must explicitly set the unused binding to the empty string"), nil
		}
		return logical.ErrorResponse("either an access group list or service ID should be provided, not both"), nil
	}

	if len(role.AccessGroupIDs) > maxGroupsPerRole {
		return logical.ErrorResponse(fmt.Sprintf("the maximum number of access groups per role is: %d", maxGroupsPerRole)), nil
	}

	if strutil.StrListContains(role.AccessGroupIDs, "AccessGroupId-PublicAccess") {
		return logical.ErrorResponse("the AccessGroupId-PublicAccess access group is not allowed on roles"), nil
	}

	// load and validate TTLs
	if ttlRaw, ok := d.GetOk(ttlField); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.TTL = time.Duration(d.Get(ttlField).(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk(maxTTLField); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.MaxTTL = time.Duration(d.Get(maxTTLField).(int)) * time.Second
	}

	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	adminToken, err := b.getAdminToken(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("error obtaining the token for the configured API key", "error", err)
		return nil, err
	}

	for _, group := range role.AccessGroupIDs {
		resp := b.iamHelper.VerifyAccessGroupExists(adminToken, group, config.Account)
		if resp != nil {
			return resp, nil
		}
	}

	if len(role.ServiceID) != 0 {
		_, resp := b.iamHelper.CheckServiceIDAccount(adminToken, role.ServiceID, config.Account)
		if resp != nil {
			return resp, nil
		}
	}

	// Store the entry.
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesStoragePath, roleName), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for role %s", roleName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

const roleHelpSyn = `Manage the Vault roles used to generate IBM Cloud credentials.`
const roleHelpDesc = `
This path allows you to read and write roles that are used to generate IBM Cloud login
credentials. These roles are associated with one or more access groups, which are used to
control permissions to IBM Cloud resources.

If the backend is mounted at "ibmcloud", you would create a Vault role at "ibmcloud/roles/my_role",
and request credentials from "ibmcloud/creds/my_role".

Each Vault role is configured with the standard ttl parameters and one or more access groups
to make the service ID member of. During the Vault role creation, all access groups specified
will be fetched and verified, and therefore must exist for the request
to succeed. When a user requests credentials against the Vault role, a new
service ID and API key will be created. The service ID will be added to the configured
access groups.
`

const roleListHelpSyn = `Lists all the roles registered with the backend.`
const roleListHelpDesc = `List existing roles by name.`

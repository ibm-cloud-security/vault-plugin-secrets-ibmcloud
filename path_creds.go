package ibmcloudsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func secretServiceIDKey(b *ibmCloudSecretBackend) *framework.Secret {
	return &framework.Secret{
		Type: secretTypeKey,
		Fields: map[string]*framework.FieldSchema{
			apiKeyField: {
				Type:        framework.TypeString,
				Description: "An API key",
			},
		},

		Renew:  b.secretKeyRenew,
		Revoke: b.secretKeyRevoke,
	}
}

func pathSecretServiceIDKey(b *ibmCloudSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("creds/%s", framework.GenericNameRegex(roleField)),
		Fields: map[string]*framework.FieldSchema{
			roleField: {
				Type:        framework.TypeString,
				Description: "Required. Name of the role.",
			},
		},
		ExistenceCheck: b.pathRoleExistenceCheck(roleField),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathServiceIDKey},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathServiceIDKey},
		},
		HelpSynopsis:    pathServiceIDKeySyn,
		HelpDescription: pathServiceIDKeyDesc,
	}
}

func (b *ibmCloudSecretBackend) pathServiceIDKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get(roleField).(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role set '%s' does not exist", roleName)), nil
	}

	return b.getSecretKey(ctx, req.Storage, role, roleName)
}

func (b *ibmCloudSecretBackend) secretKeyRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName, ok := req.Secret.InternalData[roleNameField]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing role name")
	}
	role, err := getRole(ctx, req.Storage, roleName.(string))
	if err != nil || role == nil {
		return logical.ErrorResponse(fmt.Sprintf("could not find role '%v' for secret", roleName)), nil
	}

	bindingSum, ok := req.Secret.InternalData[roleBindingHashField]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing role binding checksum")
	}
	if role.BindingHash != bindingSum.(string) {
		return logical.ErrorResponse(fmt.Sprintf("role '%v' access group or service ID bindings were updated since secret was generated, cannot renew", roleName)), nil
	}

	resp := &logical.Response{}
	resp.Secret = req.Secret
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *ibmCloudSecretBackend) secretKeyRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	adminToken, err := b.getAdminToken(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("error obtaining the token for the configured API key", "error", err)
		return nil, err
	}

	serviceIDRaw, dynamicIDSecret := req.Secret.InternalData[serviceIDField]
	apiKeyIDRaw, staticIDSecret := req.Secret.InternalData[apiKeyID]
	roleName, roleNameOK := req.Secret.InternalData[roleNameField]

	iam, resp := b.getIAMHelper(ctx, req.Storage)
	if resp != nil {
		b.Logger().Error("failed to retrieve an IAM helper", "error", resp.Error())
		return resp, nil
	}

	if dynamicIDSecret {
		err = iam.DeleteServiceID(adminToken, serviceIDRaw.(string))
		if err != nil {
			if !roleNameOK {
				roleName = "<Not Found>"
			}
			accountID := "<Not Found>"
			config, errResp := b.getConfig(ctx, req.Storage)
			if errResp == nil {
				accountID = config.Account
			}
			b.Logger().Error("An error occurred removing a service ID while revoking a secret lease. "+
				"The service ID may have been manually deleted in IBM Cloud. The administrator should verify the service ID "+
				"is removed.", "serviceID", serviceIDRaw, "vaultRole", roleName, "accountID", accountID, "deleteError", err)
			return nil, err
		}
	} else if staticIDSecret {
		err = iam.DeleteAPIKey(adminToken, apiKeyIDRaw.(string))
		if err != nil {
			if !roleNameOK {
				roleName = "<Not Found>"
			}
			accountID := "<Not Found>"
			config, errResp := b.getConfig(ctx, req.Storage)
			if errResp == nil {
				accountID = config.Account
			}
			b.Logger().Error("An error occurred removing an API key while revoking a secret lease. "+
				"The API key may have been manually deleted in IBM Cloud. The administrator should verify the API key "+
				"is removed.", "apiKeyID", apiKeyIDRaw, "vaultRole", roleName, "accountID", accountID, "deleteError", err)
			return nil, err
		}

	} else {
		msg := "secret is missing service ID or API key ID internal data"
		b.Logger().Error(msg)
		return nil, fmt.Errorf(msg)
	}

	return nil, nil
}

func (b *ibmCloudSecretBackend) getSecretKey(ctx context.Context, s logical.Storage, role *ibmCloudRole, roleName string) (*logical.Response, error) {
	config, errResp := b.getConfig(ctx, s)
	if errResp != nil {
		return errResp, nil
	}

	adminToken, err := b.getAdminToken(ctx, s)
	if err != nil {
		b.Logger().Error("error obtaining the token for the configured API key", "error", err)
		return nil, err
	}

	var resp *logical.Response
	if len(role.AccessGroupIDs) > 0 {
		resp, err = b.getSecretDynamicServiceID(ctx, s, role, adminToken, roleName, config)
		if err != nil {
			return nil, err
		}
	} else if len(role.ServiceID) > 0 {
		resp, err = b.getSecretStaticServiceID(ctx, s, role, adminToken, roleName, config)
		if err != nil {
			return nil, err
		}
		if resp.IsError() {
			return resp, nil
		}
	} else {
		return logical.ErrorResponse("role %s has neither access groups nor a service ID", roleName), nil
	}

	resp.Secret.Renewable = true
	resp.Secret.MaxTTL = role.MaxTTL
	resp.Secret.TTL = role.TTL

	return resp, nil
}

func (b *ibmCloudSecretBackend) getSecretDynamicServiceID(ctx context.Context, s logical.Storage, role *ibmCloudRole, adminToken, roleName string, config *ibmCloudConfig) (*logical.Response, error) {
	iam, resp := b.getIAMHelper(ctx, s)
	if resp != nil {
		b.Logger().Error("failed to retrieve an IAM helper", "error", resp.Error())
		return resp, nil
	}

	// Create the service ID, which is the top level object to be tracked in the secret
	// and deleted upon revocation. If any subsequent step fails, the service ID will be
	// deleted as part of WAL rollback.
	iamID, uniqueID, err := iam.CreateServiceID(adminToken, config.Account, roleName)
	if err != nil {
		return nil, err
	}

	// Write a WAL entry in case the access group assignments or API key creation process doesn't complete
	walID, err := framework.PutWAL(ctx, s, walTypeServiceID, uniqueID)
	if err != nil {
		return nil, errwrap.Wrapf("error writing WAL: {{err}}", err)
	}

	// Add service ID to access groups
	for _, group := range role.AccessGroupIDs {
		err := iam.AddServiceIDToAccessGroup(adminToken, iamID, group)
		if err != nil {
			return nil, err
		}
	}

	// Create API key
	apiKey, err := iam.CreateAPIKey(adminToken, iamID, config.Account, roleName)
	if err != nil {
		return nil, err
	}

	// Secret creation complete, delete the WAL
	if err := framework.DeleteWAL(ctx, s, walID); err != nil {
		return nil, errwrap.Wrapf("error deleting WAL: {{err}}", err)
	}

	secretD := map[string]interface{}{
		apiKeyField: apiKey.APIKey,
	}
	internalD := map[string]interface{}{
		serviceIDField:       uniqueID,
		roleNameField:        roleName,
		roleBindingHashField: role.BindingHash,
	}

	resp = b.Secret(secretTypeKey).Response(secretD, internalD)
	return resp, nil
}

func (b *ibmCloudSecretBackend) getSecretStaticServiceID(ctx context.Context, s logical.Storage, role *ibmCloudRole, adminToken, roleName string, config *ibmCloudConfig) (*logical.Response, error) {

	iam, resp := b.getIAMHelper(ctx, s)
	if resp != nil {
		b.Logger().Error("failed to retrieve an IAM helper", "error", resp.Error())
		return resp, nil
	}

	// Fetch the serviceID's IAM ID
	idInfo, resp := iam.CheckServiceIDAccount(adminToken, role.ServiceID, config.Account)
	if resp != nil {
		return resp, nil
	}
	// Create API key
	apiKey, err := iam.CreateAPIKey(adminToken, idInfo.IAMID, config.Account, roleName)
	if err != nil {
		return nil, err
	}

	secretD := map[string]interface{}{
		apiKeyField: apiKey.APIKey,
	}
	internalD := map[string]interface{}{
		apiKeyID:             apiKey.ID,
		roleNameField:        roleName,
		roleBindingHashField: role.BindingHash,
	}

	resp = b.Secret(secretTypeKey).Response(secretD, internalD)
	return resp, nil
}

const pathServiceIDKeySyn = `Generate an API key under a specific role.`
const pathServiceIDKeyDesc = `
This path will generate a new service account and associated API key.
A role, binding IBM Cloud Access Groups, will be specified
by name - for example, if this backend is mounted at "ibmcloud", then "ibmcloud/creds/deploy"
would generate service account, add it to all the access groups listed on the "deploy" role,
generate an API key for the service account and return the API key.
`

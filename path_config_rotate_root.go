package ibmcloudsecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfigRotateRoot(b *ibmCloudSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigRotateRootWrite,
			},
		},

		HelpSynopsis:    pathConfigRotateRootHelpSyn,
		HelpDescription: pathConfigRotateRootHelpDesc,
	}
}

func (b *ibmCloudSecretBackend) pathConfigRotateRootWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	/*
		config, errResp := b.getConfig(ctx, req.Storage)
		if errResp != nil {
			return errResp, nil
		}

		iam, resp := b.getIAMHelper(ctx, req.Storage)
		if resp != nil {
			b.Logger().Error("failed to retrieve an IAM helper", "error", resp.Error())
			return resp, nil
		}

		adminToken, err := b.getAdminToken(ctx, req.Storage)
		if err != nil {
			b.Logger().Error("error obtaining the token for the configured API key", "error", err)
			return nil, err
		}

		// Get the current configuration
		// cfg, err := b.getConfig(ctx, req.Storage)
		// if err != nil {
		// 	return nil, err
		// }
		// if cfg == nil {
		// 	return nil, fmt.Errorf("no configuration")
		// }
		// if cfg.CredentialsRaw == "" {
		// 	return nil, fmt.Errorf("configuration does not have credentials - this " +
		// 		"endpoint only works with user-provided JSON credentials explicitly " +
		// 		"provided via the config/ endpoint")
		// }

		oldAPIKeyIAMid := "asdf"

		// with old key, verify account == acount from the config

		// Generate a new service account key
		newAPIKey, err := iam.CreateAPIKey(adminToken, oldAPIKeyIAMid, config.Account)
		if err != nil {
			return nil, err
		}

		// Verify creds are valid

		// Update the configuration
		// cfg.CredentialsRaw = string(newCredsJSON)
		// entry, err := logical.StorageEntryJSON("config", cfg)
		// if err != nil {
		// 	return nil, errwrap.Wrapf("failed to generate new configuration: {{err}}", err)
		// }
		// if err := req.Storage.Put(ctx, entry); err != nil {
		// 	return nil, errwrap.Wrapf("failed to save new configuration: {{err}}", err)
		// }

		// Clear caches to pick up the new credentials
		//b.ClearCaches()

		// Delete the old service account key
		// oldKeyName := fmt.Sprintf("projects/%s/serviceAccounts/%s/keys/%s",
		// 	creds.ProjectId,
		// 	creds.ClientEmail,
		// 	creds.PrivateKeyId)
		// if _, err := iamAdmin.Projects.ServiceAccounts.Keys.
		// 	Delete(oldKeyName).
		// 	Context(ctx).
		// 	Do(); err != nil {
		// 	return nil, errwrap.Wrapf(fmt.Sprintf(
		// 		"failed to delete old service account key (%q) - the new service "+
		// 			"account key (%q) is active, but the old one still exists: {{err}}",
		// 		creds.PrivateKeyId, newCreds.PrivateKeyId), err)
		// }

		// return &logical.Response{
		// 	Data: map[string]interface{}{
		// 		"private_key_id": newCreds.PrivateKeyId,
		// 	},
		// }, nil
	*/

	return nil, nil
}

const pathConfigRotateRootHelpSyn = `
Request to rotate the IBM Cloud credentials used by Vault
`

const pathConfigRotateRootHelpDesc = `
This path attempts to rotate the IBM Cloud API key used by Vault
for this mount. It does this by generating a new key for the user or service ID,
replacing the internal value, and then deleting the old API key.
Note that it does not create a new service ID or user account, only a new
API key on the same IAM ID as the existing key.
`

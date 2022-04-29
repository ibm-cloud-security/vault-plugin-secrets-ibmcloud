package ibmcloudsecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *ibmCloudSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			apiKeyField: {
				Type:        framework.TypeString,
				Description: "The administrator API key.",
			},
			accountIDField: {
				Type:        framework.TypeString,
				Description: "The account ID.",
			},
			iamEndpointField: {
				Type:        framework.TypeString,
				Description: "The custom or private IAM endpoint.",
			},
		},
		ExistenceCheck: b.pathConfigExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

type ibmCloudConfig struct {
	APIKey      string `json:"api_key"`
	Account     string `json:"account"`
	IAMEndpoint string `json:"iam_endpoint"`
}

func (b *ibmCloudSecretBackend) config(ctx context.Context, s logical.Storage) (*ibmCloudConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := new(ibmCloudConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *ibmCloudSecretBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *ibmCloudSecretBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(ibmCloudConfig)
	}

	apiKey, ok := data.GetOk(apiKeyField)
	if ok {
		config.APIKey = apiKey.(string)
	} else {
		return logical.ErrorResponse("the required field %s is missing", apiKeyField), nil
	}

	accountID, ok := data.GetOk(accountIDField)
	if ok {
		config.Account = accountID.(string)
	} else {
		return logical.ErrorResponse("the required field %s is missing", accountIDField), nil
	}

	iamEndpoint, ok := data.GetOk(iamEndpointField)
	if ok {
		config.IAMEndpoint = iamEndpoint.(string)
	} else {
		config.IAMEndpoint = iamEndpointFieldDefault
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Reset backend
	b.reset()

	return nil, nil
}

func (b *ibmCloudSecretBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	displayKey := config.APIKey
	if displayKey != "" {
		displayKey = redacted
	}

	if config.IAMEndpoint == "" {
		config.IAMEndpoint = iamEndpointFieldDefault
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			apiKeyField:      displayKey,
			accountIDField:   config.Account,
			iamEndpointField: config.IAMEndpoint,
		},
	}
	return resp, nil
}

func (b *ibmCloudSecretBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")

	if err == nil {
		b.reset()
	}

	return nil, err
}

func (b *ibmCloudSecretBackend) getConfig(ctx context.Context, s logical.Storage) (*ibmCloudConfig, *logical.Response) {
	// verify the plugin is configured
	config, err := b.config(ctx, s)
	if err != nil {
		b.Logger().Error("failed to load configuration", "error", err)
		return nil, logical.ErrorResponse("no configuration was found")
	}
	if config == nil || config.APIKey == "" {
		return nil, logical.ErrorResponse("no API key was set in the configuration")
	}
	if config.Account == "" {
		return nil, logical.ErrorResponse("no account ID was set in the configuration")
	}
	if config.IAMEndpoint == "" {
		config.IAMEndpoint = iamEndpointFieldDefault
	}

	return config, nil
}

const confHelpSyn = `Configures credentials and account used for managing IAM service accounts and keys.`
const confHelpDesc = `
The IBM Cloud secrets engine requires credentials for managing IAM service accounts and keys.
This endpoint is used to configure those credentials. The API key provided must have the following permissions:
Editor on Access Groups Service and Operator on IAM Identity Service.`

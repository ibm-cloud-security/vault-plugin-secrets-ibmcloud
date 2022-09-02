package ibmcloudsecrets

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig_Write(t *testing.T) {
	b, s := testBackend(t)

	configData := map[string]interface{}{}
	if err := testConfigCreate(t, b, s, configData); err == nil {
		t.Fatal("expected error")
	}

	configData = map[string]interface{}{
		apiKeyField:    "theAPIKey",
		accountIDField: "theAccount",
	}
	if err := testConfigCreate(t, b, s, configData); err != nil {
		t.Fatalf("err: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil {
		keyVal, ok := resp.Data[apiKeyField]
		if !ok {
			t.Fatal("the api_key field was not found in the read config")
		}
		if keyVal != redacted {
			t.Fatal("the api_key value was not redacted")
		}
		_, ok = resp.Data[accountIDField]
		if !ok {
			t.Fatal("the account_id field was not found in the read config")
		}
		keyVal, ok = resp.Data[iamEndpointField]
		if !ok {
			t.Fatal("the iam_endpoint field was not found in the read config")
		}
		if keyVal != iamEndpointDefault {
			t.Fatal("the iam_endpoint was not defaulted as expected")
		}
		keyVal, ok = resp.Data[resourceControllerEndpointField]
		if !ok {
			t.Fatalf("the %s field was not found in the read config", resourceControllerEndpointField)
		}
		if keyVal != resourceControllerEndpointDefault {
			t.Fatalf("the %s field was not found in the read config", resourceControllerEndpointField)
		}

	} else {
		t.Fatal("did not get a response from the read post-create")
	}
}

func TestConfig_WriteIAMEndpoint(t *testing.T) {
	testCustomEndpointWrite(t, iamEndpointField)
}

func TestConfig_WriteResourceControllerEndpoint(t *testing.T) {
	testCustomEndpointWrite(t, resourceControllerEndpointField)
}

func testCustomEndpointWrite(t *testing.T, configField string) {
	t.Helper()
	b, s := testBackend(t)

	configData := map[string]interface{}{}
	if err := testConfigCreate(t, b, s, configData); err == nil {
		t.Fatal("expected error")
	}

	testEndpoint := "https://custom.domain.test"
	configData = map[string]interface{}{
		apiKeyField:    "theAPIKey",
		accountIDField: "theAccount",
		configField:    testEndpoint,
	}
	if err := testConfigCreate(t, b, s, configData); err != nil {
		t.Fatalf("err: %v", err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil {
		keyVal, ok := resp.Data[configField]
		if !ok {
			t.Fatalf("the %s field was not found in the read config", configField)
		}
		if keyVal != testEndpoint {
			t.Fatalf("the %s was not set as expected", configField)
		}
	} else {
		t.Fatal("did not get a response from the read post-create")
	}
}

func TestConfigDelete(t *testing.T) {
	b, s := testBackend(t)

	configData := map[string]interface{}{
		apiKeyField:    "theAPIKey",
		accountIDField: "theAccount",
	}

	if err := testConfigCreate(t, b, s, configData); err != nil {
		t.Fatalf("err: %v", err)
	}

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil {
		t.Fatal("expected nil config after delete")
	}
}

func testConfigCreate(t *testing.T, b *ibmCloudSecretBackend, s logical.Storage, d map[string]interface{}) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return err
	}
	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func TestLoadOfPreviousConfig(t *testing.T) {
	b, s := testBackend(t)

	// set config without endpoint default set, mimicking a v0.1.0 config
	config, err := b.config(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if config == nil {
		config = new(ibmCloudConfig)
	}
	config.APIKey = "key"
	config.Account = "account"

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	// Load the config and verify the endpoints are defaulted
	newConfig, resp := b.getConfig(context.Background(), s)
	if resp != nil {
		t.Fatal(resp.Error())
	}

	if newConfig.IAMEndpoint != iamEndpointDefault {
		t.Fatalf("The config's IAM Endpoint was not defaulted correctly on the load of a previous version config")
	}
	if newConfig.ResourceControllerEndpoint != resourceControllerEndpointDefault {
		t.Fatalf("The config's IAM Endpoint was not defaulted correctly on the load of a previous version config")
	}
}

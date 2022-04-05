package ibmcloudsecrets

import (
	"context"
	"fmt"
	"testing"
	"time"

	gomock "github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/logical"
)

/* TODO test
test before config is set

test with no API in config

test happy path
*/
func TestConfigRotateRootSuccess(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockHelper := NewMockiamHelper(ctrl)

	// Set up the config, the iamHelper mocks, and the backend
	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}

	mockHelper.EXPECT().ObtainToken("adminKey").Return("AdminToken", nil)
	mockHelper.EXPECT().VerifyToken(gomock.Any(), "AdminToken").Return(&tokenInfo{Expiry: time.Now().Add(time.Hour)}, nil)

	mockHelper.EXPECT().GetAPIKeyDetails("AdminToken", "adminKey").
		Return(&APIKeyDetailsResponse{ID: "oldID", IAMID: "testIAMID", AccountID: "testAccountID"}, nil)
	mockHelper.EXPECT().CreateAPIKey("AdminToken", "testIAMID", "testAccountID", gomock.Any(), gomock.Any()).
		Return(&APIKeyV1Response{APIKey: "newKeyVal", ID: "newKeyID"}, nil)

	mockHelper.EXPECT().Cleanup()

	mockHelper.EXPECT().DeleteAPIKey("AdminToken", "oldID").Return(nil)

	b, s := testBackend(t)

	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}
	b.iamHelper = mockHelper

	// Rotate the key
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("err: %v", resp.Error())
	}

	// Verify the API key was updated in the config
	config, resp := b.getConfig(context.Background(), s)
	if resp != nil {
		t.Fatalf("err: %v", resp.Error())
	}

	if config.APIKey != "newKeyVal" {
		t.Fatalf("the API key was no set as expected. Received %s. Expected %s", config.APIKey, "newKeyVal")
	}

}

func TestRotateCreateFails(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockHelper := NewMockiamHelper(ctrl)

	// Set up the config, the iamHelper mocks, and the backend
	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}

	mockHelper.EXPECT().ObtainToken("adminKey").Return("AdminToken", nil)
	mockHelper.EXPECT().VerifyToken(gomock.Any(), "AdminToken").Return(&tokenInfo{Expiry: time.Now().Add(time.Hour)}, nil)

	mockHelper.EXPECT().GetAPIKeyDetails("AdminToken", "adminKey").
		Return(&APIKeyDetailsResponse{ID: "oldID", IAMID: "testIAMID", AccountID: "testAccountID"}, nil)
	mockHelper.EXPECT().CreateAPIKey("AdminToken", "testIAMID", "testAccountID", gomock.Any(), gomock.Any()).
		Return(nil, fmt.Errorf("intentional CreateAPIKey mock failure"))

	b, s := testBackend(t)

	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}
	b.iamHelper = mockHelper

	// Rotate the key
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
	})

	// Verify the expected create failure is received
	if resp != nil {
		t.Fatalf("error: received a response when none was expected: %v", resp)
	}

	if err == nil {
		t.Fatalf("error: did not receive an error from the rotation as expected")
	}

	if err.Error() != "intentional CreateAPIKey mock failure" {
		t.Fatalf("error: did not receive the expected error message. Received this instead %s", err.Error())
	}

	// Verify the API key was not updated in the config
	config, resp := b.getConfig(context.Background(), s)
	if resp != nil {
		t.Fatalf("err: %v", resp.Error())
	}

	if config.APIKey != "adminKey" {
		t.Fatalf("the API key was no set as expected. Received %s. Expected %s", config.APIKey, "adminKey")
	}
}

/*
	TODO test

    test before config is set
    test with no API key set
    test with API key creation failure
    test with API key deletion failure
*/

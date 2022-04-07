package ibmcloudsecrets

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	gomock "github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/logical"
)

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

	// verify the new API key ID was returned in the response
	keyID, ok := resp.Data[apiKeyID]
	if !ok {
		t.Fatal("the api_key_id field was not found in the response")
	}

	if keyID != "newKeyID" {
		t.Fatal("the new API key ID was not the expected value in the response")
	}

	// Verify the API key was updated in the config
	config, resp := b.getConfig(context.Background(), s)
	if resp != nil {
		t.Fatalf("err: %v", resp.Error())
	}

	if config.APIKey != "newKeyVal" {
		t.Fatalf("the API key was not set as expected. Received %s. Expected %s", config.APIKey, "newKeyVal")
	}
}

func TestRotateCreateFails(t *testing.T) {
	// Test the case when creating the new API key fails

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

func TestRotateDeleteKeyFails(t *testing.T) {
	// Test the case where the key is rotated but the deletion of the old key fails
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

	mockHelper.EXPECT().DeleteAPIKey("AdminToken", "oldID").
		Return(fmt.Errorf("intentional DeleteAPIKey mock failure"))

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
	if resp == nil {
		t.Fatalf("error: a response was expected, but none was received")
	}

	if err == nil {
		t.Fatalf("error: did not receive an error from the rotation as expected")
	}

	if err.Error() != "intentional DeleteAPIKey mock failure" {
		t.Fatalf("error: did not receive the expected error message. Received this instead %s", err.Error())
	}

	// verify the response error has both the old and new key IDs in it
	if !strings.Contains(resp.Error().Error(), "oldID") {
		t.Fatalf("expected %s to be in error %v", "oldID", resp.Error())
	}
	if !strings.Contains(resp.Error().Error(), "newKeyID") {
		t.Fatalf("expected %s to be in error %v", "newKeyID", resp.Error())
	}

	// Verify the API key was updated in the config
	config, resp := b.getConfig(context.Background(), s)
	if resp != nil {
		t.Fatalf("err: %v", resp.Error())
	}

	if config.APIKey != "newKeyVal" {
		t.Fatalf("the API key was not set as expected. Received %s. Expected %s", config.APIKey, "newKeyVal")
	}
}

func TestConfigRotateNoConfigSet(t *testing.T) {
	// Test with no config set
	b, s := testBackend(t)

	// Rotate the key
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedMsg := "no API key was set in the configuration"
	if resp == nil {
		t.Fatalf("expected an error response on rotation but did not receive one")
	} else if !strings.Contains(resp.Error().Error(), expectedMsg) {
		t.Fatalf("expected message \"%s\" to be in error: %v", expectedMsg, resp.Error())
	}

	// Test when the key is set to the empty string
	var configData = map[string]interface{}{
		apiKeyField:    "",
		accountIDField: "",
	}
	err = testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}

	// Rotate the key
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp == nil {
		t.Fatalf("expected an error response on rotation but did not receive one")
	} else if !strings.Contains(resp.Error().Error(), expectedMsg) {
		t.Fatalf("expected message \"%s\" to be in error: %v", expectedMsg, resp.Error())
	}
}

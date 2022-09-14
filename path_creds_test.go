package ibmcloudsecrets

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestStaticServiceID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Set up
	callCount := map[string]int{
		"CheckServiceIDAccount": 9,
		"CreateAPIKey":          4,
	}

	b, s := getMockedBackendStaticServiceID(t, ctrl, callCount)

	// Test successful Get
	testRoleCreate(t, b, s, map[string]interface{}{nameField: "testRole", serviceIDField: "serviceID1"})
	sec := testSuccessfulGet(t, b, s, map[string]string{apiKeyField: "theAPIKey"}, map[string]string{apiKeyID: "apiKeyID"}, 0, 0)

	// Test successful renew and revoke
	testSuccessfulRenew(t, b, s, sec)
	testSuccessfulRevoke(t, b, s, sec)

	// Update role with TTLs set
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", serviceIDField: "serviceID1", ttlField: 1000, maxTTLField: 2000})
	// Test successful Get, verify TTLs
	sec = testSuccessfulGet(t, b, s, map[string]string{apiKeyField: "theAPIKey"}, map[string]string{apiKeyID: "apiKeyID"}, 1000, 2000)

	// Update role to different user
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", serviceIDField: "serviceID2"})

	// Test failure to renew
	testRenewFailureWithChangedBindings(t, b, s, sec)

	// Test failure to get a credential
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", serviceIDField: "keyFailureGetUser"})
	testFailedGet(t, b, s)

	// Test failure to renew when the role has been deleted
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", serviceIDField: "serviceID1"})
	sec = testSuccessfulGet(t, b, s, map[string]string{apiKeyField: "theAPIKey"}, map[string]string{apiKeyID: "apiKeyID"}, 1000, 2000)
	testRoleDelete(t, b, s, "testRole")
	testRenewFailureWithDeletedRole(t, b, s, sec)

}

func TestDynamicServiceID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Set up
	callCount := map[string]int{
		"CreateServiceID":           4,
		"CreateAPIKey":              3,
		"DeleteServiceID":           1,
		"VerifyAccessGroupExists":   16,
		"AddServiceIDToAccessGroup": 12,
	}

	b, s := getMockedBackendDynamicServiceID(t, ctrl, callCount)

	// Test successful Get
	accessGroups := []string{"a", "b", "c"}
	testRoleCreate(t, b, s, map[string]interface{}{nameField: "testRole", accessGroupIDsField: accessGroups})
	sec := testSuccessfulGet(t, b, s, map[string]string{apiKeyField: "theAPIKey"}, map[string]string{serviceIDField: "createdServiceID"}, 0, 0)

	// Test successful renew and revoke
	testSuccessfulRenew(t, b, s, sec)
	testSuccessfulRevoke(t, b, s, sec)

	// Update role with TTLs set
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", accessGroupIDsField: accessGroups, ttlField: 1000, maxTTLField: 2000})
	// Test successful Get, verify TTLs
	sec = testSuccessfulGet(t, b, s, map[string]string{apiKeyField: "theAPIKey"}, map[string]string{serviceIDField: "createdServiceID"}, 1000, 2000)

	// Update role to add a group
	accessGroups = append(accessGroups, "d")
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", accessGroupIDsField: accessGroups})

	// Test failure to renew
	testRenewFailureWithChangedBindings(t, b, s, sec)

	// Test failure to get a credential
	accessGroups = append(accessGroups, "groupToTriggerFailure")
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", accessGroupIDsField: accessGroups})
	testFailedGet(t, b, s)

	// Test failure to renew when the role has been deleted
	accessGroups = []string{"a"}
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", accessGroupIDsField: accessGroups})
	sec = testSuccessfulGet(t, b, s, map[string]string{apiKeyField: "theAPIKey"}, map[string]string{serviceIDField: "createdServiceID"}, 1000, 2000)
	testRoleDelete(t, b, s, "testRole")
	testRenewFailureWithDeletedRole(t, b, s, sec)

}

func TestDynamicServiceIDWithHMACKeys(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Set up
	callCount := map[string]int{
		"CreateCOSResourceKey":         5, // 4 successful, 1 failed cred get
		"DeleteCOSResourceKey":         1,
		"VerifyAccessGroupExists":      20, // the number of times role create or update is called time the number access group
		"AddServiceIDToAccessGroup":    16, // the number of times role create or update is called time the number access group
		"VerifyResourceInstanceExists": 1,
		"GetAPIKeyDetails":             6,  // 4 successful get credentials, 1 failed get credentials, 1 for config validation
		"GetPolicyIDs":                 5,  // 4 successful get credentials, 1 failed get credentials
		"DeletePolicy":                 10, // 4 successful get credentials, 1 failed get credentials x 2 policies per call
	}

	b, s := getMockedBackendDynamicServiceIDWithHMACKeys(t, ctrl, callCount)

	// Test successful Get
	accessGroups := []string{"a", "b", "c"}
	cosGUID := "theCOSGUID"
	testRoleCreate(t, b, s, map[string]interface{}{nameField: "testRole", cosInstanceGUIDField: cosGUID, accessGroupIDsField: accessGroups})

	expectedCredData := map[string]string{apiKeyField: "apiKeyValue", accessKeyIDField: "accessKeyID", secretAccessKeyField: "secretAccessKey"}
	expectedInternalData := map[string]string{resourceKeyGUIDField: "resourceKeyGUID"}
	sec := testSuccessfulGet(t, b, s, expectedCredData, expectedInternalData, 0, 0)

	// Test successful renew and revoke
	testSuccessfulRenew(t, b, s, sec)
	testSuccessfulRevoke(t, b, s, sec)

	// Update role with TTLs set
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", cosInstanceGUIDField: cosGUID, accessGroupIDsField: accessGroups, ttlField: 1000, maxTTLField: 2000})
	// Test successful Get, verify TTLs
	sec = testSuccessfulGet(t, b, s, expectedCredData, expectedInternalData, 1000, 2000)

	// Test trying to renew a credential after the role has been updated to have new access groups
	accessGroups = append(accessGroups, "d")
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", cosInstanceGUIDField: cosGUID, accessGroupIDsField: accessGroups})
	testRenewFailureWithChangedBindings(t, b, s, sec)

	// Test trying to renew a credential after the role has an updated the COS instance
	sec = testSuccessfulGet(t, b, s, expectedCredData, expectedInternalData, 0, 0)
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", cosInstanceGUIDField: "newCOSGUID", accessGroupIDsField: accessGroups})
	testRenewFailureWithChangedBindings(t, b, s, sec)

	// Test failure to get a credential
	accessGroups = append(accessGroups, "groupToTriggerFailure")
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", cosInstanceGUIDField: cosGUID, accessGroupIDsField: accessGroups})
	testFailedGet(t, b, s)

	// Test failure to renew when the role has been deleted
	accessGroups = []string{"a"}
	testRoleUpdate(t, b, s, map[string]interface{}{nameField: "testRole", accessGroupIDsField: accessGroups})
	sec = testSuccessfulGet(t, b, s, expectedCredData, expectedInternalData, 1000, 2000)
	testRoleDelete(t, b, s, "testRole")
	testRenewFailureWithDeletedRole(t, b, s, sec)

}

func TestStaticServiceIDDeleted(t *testing.T) {
	// simulating a service ID being deleted directly in IBM Cloud or other ID checking failure
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Set up
	b, s := getMockedBackendStaticServiceIDDeleteTest(t, ctrl)

	testRoleCreate(t, b, s, map[string]interface{}{nameField: "testRole", serviceIDField: "serviceID1"})
	// Test failed get
	testFailedGet(t, b, s)
}

/*
Tests a successful Get (read) of a credential and validates the returned Secret.
The internalData parameter is used to pass in key-values that differ between static and dynamic service ID credentials.
If the ttl and maxTTL values are greater than 0 they will be used to check the Secret's lease.
*/
func testSuccessfulGet(t *testing.T, b *ibmCloudSecretBackend, s logical.Storage, data map[string]string, internalData map[string]string, ttl, maxTTL int) *logical.Secret {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/testRole",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("\nunexpected error: %s", err.Error())
	}
	if resp.IsError() {
		t.Fatalf("expected no response error, actual:%#v", resp.Error())
	}
	if resp == nil || resp.Secret == nil {
		t.Fatalf("expected response with secret, got response: %v", resp)
	}
	// Verify the response
	for k, expected := range data {
		received, ok := resp.Data[k]
		if !ok {
			t.Fatalf("the credential does not have the expected key: %s", k)
		}
		if received.(string) != expected {
			t.Fatalf("expected a credential with key-value %s=%s, but received %s=%s", k, expected, k, received)
		}
	}
	// Verify the received Data does not have keys that were unexpected
	for k, v := range resp.Data {
		// TODO add test to only allow COS HMAC keys to missing from the expected data, and then only if
		// the response has them as zero length
		if _, ok := data[k]; !ok {
			t.Fatalf("received a credential with and unexpected key %s with value %s", k, v)
		}
	}

	for k, v := range internalData {
		testV, ok := resp.Secret.InternalData[k]
		if !ok {
			t.Fatalf("did not find key %s in the Secret's InternalData", k)
		}
		if testV.(string) != v {
			t.Fatalf("found %s=%s in the Secret's InternalData. expected %s=%s", k, testV, k, v)
		}
	}

	if resp.Secret.InternalData[roleNameField].(string) != "testRole" {
		t.Fatalf("the internal data does not contain the expected role name")
	}
	if _, ok := resp.Secret.InternalData[roleBindingHashField]; !ok {
		t.Fatalf("the internal data does not contain the role binding hash")
	}
	if ttl > 0 && int(resp.Secret.LeaseTotal().Seconds()) != ttl {
		t.Fatalf("expected lease duration %d, got %d", ttl, int(resp.Secret.LeaseTotal().Seconds()))
	}

	if maxTTL > 0 && int(resp.Secret.LeaseOptions.MaxTTL.Seconds()) != maxTTL {
		t.Fatalf("expected max lease %d, got %d", maxTTL, int(resp.Secret.LeaseOptions.MaxTTL.Seconds()))
	}

	return resp.Secret
}

func testFailedGet(t *testing.T, b *ibmCloudSecretBackend, s logical.Storage) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/testRole",
		Storage:   s,
	})
	if (err == nil) && (resp == nil || !resp.IsError()) {
		t.Fatalf("expected an error, or an error Response, actual returns: resp:%#v err:%#v", resp, err)
	}
}

func testSuccessfulRenew(t *testing.T, b *ibmCloudSecretBackend, s logical.Storage, sec *logical.Secret) {
	t.Helper()
	sec.IssueTime = time.Now()
	sec.Increment = time.Hour
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Secret:    sec,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("got error while trying to renew: %v", err)
	} else if resp.IsError() {
		t.Fatalf("got error while trying to renew: %v", resp.Error())
	}
}

func testSuccessfulRevoke(t *testing.T, b *ibmCloudSecretBackend, s logical.Storage, sec *logical.Secret) {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    sec,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

func testRenewFailureWithChangedBindings(t *testing.T, b *ibmCloudSecretBackend, s logical.Storage, sec *logical.Secret) {
	t.Helper()
	sec.IssueTime = time.Now()
	sec.Increment = time.Hour
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Secret:    sec,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedMsg := "access group or service ID bindings were updated since secret was generated, cannot renew"
	if resp == nil {
		t.Fatalf("expected an error response on renew but did not receive one")
	} else if !strings.Contains(resp.Error().Error(), expectedMsg) {
		t.Fatalf("expected message \"%s\" to be in error: %v", expectedMsg, resp.Error())
	}
}

func testRenewFailureWithDeletedRole(t *testing.T, b *ibmCloudSecretBackend, s logical.Storage, sec *logical.Secret) {
	t.Helper()
	sec.IssueTime = time.Now()
	sec.Increment = time.Hour
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Secret:    sec,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedMsg := "could not find role 'testRole' for secret"
	if resp == nil {
		t.Fatalf("expected an error response on renew but did not receive one")
	} else if !strings.Contains(resp.Error().Error(), expectedMsg) {
		t.Fatalf("expected message \"%s\" to be in error: %v", expectedMsg, resp.Error())
	}
}

// TestServiceID_WAL_Cleanup tests that any service ID that gets created, but
// fails to have an API key created for it, gets cleaned up by the periodic WAL
// function.
func TestServiceID_WAL_Cleanup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	callCount := map[string]int{
		"VerifyAccessGroupExists":   1,
		"CreateServiceID":           1,
		"AddServiceIDToAccessGroup": 1,
		"CreateAPIKey":              1,
		"DeleteServiceID":           1,
	}

	b, s := getMockedBackendDynamicServiceID(t, ctrl, callCount)

	wal, _ := framework.ListWAL(context.Background(), s)
	if len(wal) != 0 {
		t.Fatalf("The WAL is not empty at the start of the test.")
	}

	accessGroups := []string{"a"}
	testRoleCreate(t, b, s, map[string]interface{}{nameField: "APIKeyErrorRole", accessGroupIDsField: accessGroups})

	// create a short timeout to short-circuit the retry process and trigger the
	// deadline error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/APIKeyErrorRole",
		Storage:   s,
	})
	if err == nil {
		t.Fatalf("expected an error, but did not receive one")
	}
	if resp != nil {
		t.Fatalf("expected no response, but received:%#v", resp)
	}

	if !strings.Contains(err.Error(), "intentional test error from mock CreateAPIKey") {
		t.Fatalf("expected intentional error from mock, but got '%s'", err.Error())
	}

	assertEmptyWAL(t, b, s)
}

// TestResourceKey_WAL_Cleanup tests that any resource key that gets created, but
// fails to complete the other credential creation steps, gets cleaned up by the periodic WAL
// function.
func TestResourceKey_WAL_Cleanup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	callCount := map[string]int{
		"CreateCOSResourceKey":         1,
		"VerifyAccessGroupExists":      1,
		"AddServiceIDToAccessGroup":    1,
		"VerifyResourceInstanceExists": 1,
		"GetAPIKeyDetails":             2,
		"GetPolicyIDs":                 1,
		"DeletePolicy":                 2,
		"DeleteCOSResourceKey":         1,
	}

	b, s := getMockedBackendDynamicServiceIDWithHMACKeys(t, ctrl, callCount)

	wal, _ := framework.ListWAL(context.Background(), s)
	if len(wal) != 0 {
		t.Fatalf("The WAL is not empty at the start of the test.")
	}

	accessGroups := []string{"groupToTriggerFailure"}
	testRoleCreate(t, b, s, map[string]interface{}{nameField: "testRole", accessGroupIDsField: accessGroups, cosInstanceGUIDField: "theCOSGUID"})

	// create a short timeout to short-circuit the retry process and trigger the
	// deadline error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/testRole",
		Storage:   s,
	})
	if err == nil {
		t.Fatalf("expected an error, but did not receive one")
	}
	if resp != nil {
		t.Fatalf("expected no response, but received:%#v", resp)
	}

	if !strings.Contains(err.Error(), "groupToTriggerFailure") {
		t.Fatalf("expected intentional error from mock, but got '%s'", err.Error())
	}

	assertEmptyWAL(t, b, s)
}

func assertEmptyWAL(t *testing.T, b *ibmCloudSecretBackend, s logical.Storage) {
	t.Helper()

	wal, err := framework.ListWAL(context.Background(), s)
	if err != nil {
		t.Fatalf("error listing wal: %s", err)
	}
	req := &logical.Request{
		Storage: s,
	}

	// loop of WAL entries and trigger the rollback method for each, simulating
	// Vault's rollback mechanism
	for _, v := range wal {
		ctx := context.Background()
		entry, err := framework.GetWAL(ctx, s, v)
		if err != nil {
			t.Fatal(err)
		}

		err = b.walRollback(ctx, req, entry.Kind, entry.Data)
		if err != nil {
			t.Fatal(err)
		}
		if err := framework.DeleteWAL(ctx, s, v); err != nil {
			t.Fatal(err)
		}
	}
}

func getMockedBackendStaticServiceID(t *testing.T, ctrl *gomock.Controller, callCount map[string]int) (*ibmCloudSecretBackend, logical.Storage) {
	t.Helper()

	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}
	adminToken := "AdminToken"
	mockHelper := NewMockapiHelper(ctrl)
	// For the adminKey we always return AdminToken, this lets enforce that the code is correctly using the admin token
	// for the IBM Cloud API calls calls.
	mockHelper.EXPECT().ObtainToken("adminKey").Return(adminToken, nil)
	mockHelper.EXPECT().VerifyToken(gomock.Any(), adminToken).Return(&tokenInfo{Expiry: time.Now().Add(time.Hour)}, nil)
	mockHelper.EXPECT().GetAPIKeyDetails("AdminToken", "adminKey").
		Return(&APIKeyDetailsResponse{ID: "oldID", IAMID: "testIAMID", AccountID: "theAccountID"}, nil)

	// Mock for create / update of the test role and the look up of the service ID's IAM ID
	mockHelper.EXPECT().CheckServiceIDAccount(adminToken, gomock.Any(), "theAccountID").
		Times(callCount["CheckServiceIDAccount"]).
		DoAndReturn(func(iamToken, serviceID, accountID string) (*serviceIDv1Response, *logical.Response) {
			if !strutil.StrListContains([]string{"serviceID1", "serviceID2", "keyFailureGetUser"}, serviceID) {
				return nil, logical.ErrorResponse("CheckServiceIDAccount error with %s", serviceID)
			}
			return &serviceIDv1Response{ID: "serviceID1", IAMID: fmt.Sprintf("%s_iam", serviceID)}, nil
		})

	mockHelper.EXPECT().CreateAPIKey(adminToken, gomock.Any(), "theAccountID", gomock.Any(), gomock.Any()).
		Times(callCount["CreateAPIKey"]).
		DoAndReturn(func(iamToken, iamID, accountID, name, description string) (*APIKeyV1Response, error) {
			roleName := "testRole"
			if !strings.Contains(name, roleName) {
				t.Fatalf("expected %s to be in the key name %s", roleName, name)
			}
			if !strings.Contains(description, roleName) {
				t.Fatalf("expected %s to be in the key description %s", roleName, description)
			}

			if iamID == "keyFailureGetUser_iam" {
				return nil, fmt.Errorf("intentional CreateAPIKey mock failure")
			}
			return &APIKeyV1Response{ID: "apiKeyID", APIKey: "theAPIKey"}, nil
		})

	mockHelper.EXPECT().DeleteAPIKey(adminToken, "apiKeyID").
		Return(nil)

	b, s := testBackend(t)
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}
	b.apiHelper = mockHelper

	return b, s
}

func getMockedBackendDynamicServiceID(t *testing.T, ctrl *gomock.Controller, callCount map[string]int) (*ibmCloudSecretBackend, logical.Storage) {
	t.Helper()

	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}

	adminToken := "AdminToken"
	mockHelper := NewMockapiHelper(ctrl)
	// For the adminKey we always return AdminToken, this lets enforce that the code is correctly using the admin token
	// for the IBM Cloud API calls calls.
	mockHelper.EXPECT().ObtainToken("adminKey").Return(adminToken, nil)
	mockHelper.EXPECT().VerifyToken(gomock.Any(), adminToken).Return(&tokenInfo{Expiry: time.Now().Add(time.Hour)}, nil)
	mockHelper.EXPECT().GetAPIKeyDetails("AdminToken", "adminKey").
		Return(&APIKeyDetailsResponse{ID: "oldID", IAMID: "testIAMID", AccountID: "theAccountID"}, nil)

	// Mock for create / update of the test role and the look up of the service ID's IAM ID
	mockHelper.EXPECT().VerifyAccessGroupExists(adminToken, gomock.Any(), "theAccountID").
		Times(callCount["VerifyAccessGroupExists"]).
		DoAndReturn(func(iamToken, group, accountID string) (*logical.Response, error) {
			if !strutil.StrListContains([]string{"a", "b", "c", "d", "groupToTriggerFailure"}, group) {
				return logical.ErrorResponse("VerifyAccessGroupExists error with %s", group), nil
			}
			return nil, nil
		})

	// Mocks for getSecretDynamicServiceID

	mockHelper.EXPECT().CreateServiceID(adminToken, "theAccountID", gomock.Any()).
		Times(callCount["CreateServiceID"]).
		DoAndReturn(func(iamToken, accountID, roleName string) (string, string, error) {
			if roleName != "testRole" && roleName != "APIKeyErrorRole" {
				return "", "", fmt.Errorf("unexpected role name in CreateServiceID: %s", roleName)
			}
			return "createdServiceID_iam", "createdServiceID", nil
		})

	mockHelper.EXPECT().AddServiceIDToAccessGroup(adminToken, "createdServiceID_iam", gomock.Any()).
		Times(callCount["AddServiceIDToAccessGroup"]).
		DoAndReturn(func(iamToken, iamID, group string) error {
			if !strutil.StrListContains([]string{"a", "b", "c", "d"}, group) {
				return fmt.Errorf("AddServiceIDToAccessGroup error with group %s", group)
			}
			return nil
		})

	mockHelper.EXPECT().CreateAPIKey(adminToken, "createdServiceID_iam", "theAccountID", gomock.Any(), gomock.Any()).
		Times(callCount["CreateAPIKey"]).
		DoAndReturn(func(iamToken, iamID, accountID, name, description string) (*APIKeyV1Response, error) {
			if strings.Contains(name, "testRole") {
				if !strings.Contains(description, "testRole") {
					t.Fatalf("expected %s to be in the key description %s", "testRole", description)
				}
				return &APIKeyV1Response{ID: "apiKeyID", APIKey: "theAPIKey"}, nil
			} else if strings.Contains(name, "APIKeyErrorRole") {
				if !strings.Contains(description, "APIKeyErrorRole") {
					t.Fatalf("expected %s to be in the key description %s", "APIKeyErrorRole", description)
				}
				return nil, fmt.Errorf("intentional test error from mock CreateAPIKey")
			} else {
				return nil, fmt.Errorf("unexpected key name in CreateAPIKey mock: %s", name)
			}
		})

	// Mock for revoke
	mockHelper.EXPECT().DeleteServiceID(adminToken, "createdServiceID").Times(callCount["DeleteServiceID"]).Return(nil)

	b, s := testBackend(t)
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}
	b.apiHelper = mockHelper

	return b, s
}

func getMockedBackendDynamicServiceIDWithHMACKeys(t *testing.T, ctrl *gomock.Controller, callCount map[string]int) (*ibmCloudSecretBackend, logical.Storage) {
	t.Helper()

	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}

	adminToken := "AdminToken"
	apiKey := "apiKeyValue"
	serviceIDIAM := "resourceKeyServiceID"

	mockHelper := NewMockapiHelper(ctrl)
	// For the adminKey we always return AdminToken, this lets enforce that the code is correctly using the admin token
	// for the IBM Cloud API calls calls.
	mockHelper.EXPECT().ObtainToken("adminKey").Return(adminToken, nil)
	mockHelper.EXPECT().VerifyToken(gomock.Any(), adminToken).Return(&tokenInfo{Expiry: time.Now().Add(time.Hour)}, nil)

	// GetAPIKeyDetails is used for the backend configuration
	// as well as the main flow of getSecretDynamicServiceIDWithHMACKey
	// This mock covers both
	mockHelper.EXPECT().GetAPIKeyDetails(adminToken, gomock.Any()).
		Times(callCount["GetAPIKeyDetails"]).
		DoAndReturn(func(token, key string) (*APIKeyDetailsResponse, error) {
			if key == "adminKey" {
				return &APIKeyDetailsResponse{ID: "unused", IAMID: "unused", AccountID: "theAccountID"}, nil
			} else if key == apiKey {
				return &APIKeyDetailsResponse{ID: "unused", IAMID: serviceIDIAM, AccountID: "unused"}, nil
			} else {
				t.Fatal("unexpected API key value in mocked GetAPIKeyDetails:", key)
			}
			return nil, nil
		})
	// Mock for create / update of the test role and the look up of the COS instance
	mockHelper.EXPECT().VerifyAccessGroupExists(adminToken, gomock.Any(), "theAccountID").
		Times(callCount["VerifyAccessGroupExists"]).
		DoAndReturn(func(iamToken, group, accountID string) (*logical.Response, error) {
			if !strutil.StrListContains([]string{"a", "b", "c", "d", "groupToTriggerFailure"}, group) {
				return logical.ErrorResponse("VerifyAccessGroupExists error with %s", group), nil
			}
			return nil, nil
		})
	mockHelper.EXPECT().VerifyResourceInstanceExists("AdminToken", gomock.Any()).
		MinTimes(callCount["VerifyResourceInstanceExists"]).Return(nil)

	// Mocks for getSecretDynamicServiceIDWithHMACKey
	resourceKeyGUID := "resourceKeyGUID"
	accessKeyID := "accessKeyID"
	secretAccessKey := "secretAccessKey"

	mockHelper.EXPECT().CreateCOSResourceKey(adminToken, "theCOSGUID", "testRole").
		Times(callCount["CreateCOSResourceKey"]).
		DoAndReturn(func(iamToken, cosGUID, roleName string) (string, string, string, string, error) {
			if roleName != "testRole" {
				return "", "", "", "", fmt.Errorf("unexpected role name in CreateCOSResourceKey: %s", roleName)
			}
			return resourceKeyGUID, apiKey, accessKeyID, secretAccessKey, nil
		})

	mockHelper.EXPECT().GetPolicyIDs("AdminToken", "theAccountID", serviceIDIAM).
		Times(callCount["GetPolicyIDs"]).
		Return([]string{"p1", "p2"}, nil)

	expectedPolicies := []string{"p1", "p2", "p1", "p2", "p1", "p2", "p1", "p2", "p1", "p2"}
	mockHelper.EXPECT().DeletePolicy("AdminToken", gomock.Any()).
		Times(callCount["DeletePolicy"]).
		DoAndReturn(func(iamToken, policy string) error {
			if len(expectedPolicies) == 0 {
				t.Fatal("DeletePolicy was called too many times")
			}
			if policy != expectedPolicies[0] {
				t.Fatal("Unexpected policy, or policies called out of order:", policy)
			}
			expectedPolicies = expectedPolicies[1:]
			return nil
		})

	mockHelper.EXPECT().AddServiceIDToAccessGroup(adminToken, serviceIDIAM, gomock.Any()).
		Times(callCount["AddServiceIDToAccessGroup"]).
		DoAndReturn(func(iamToken, iamID, group string) error {
			if !strutil.StrListContains([]string{"a", "b", "c", "d"}, group) {
				return fmt.Errorf("AddServiceIDToAccessGroup error with group %s", group)
			}
			return nil
		})

	// Mock for revoke
	mockHelper.EXPECT().DeleteCOSResourceKey(adminToken, resourceKeyGUID).Times(callCount["DeleteCOSResourceKey"]).Return(nil)

	b, s := testBackend(t)
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}
	b.apiHelper = mockHelper

	return b, s
}

func getMockedBackendStaticServiceIDDeleteTest(t *testing.T, ctrl *gomock.Controller) (*ibmCloudSecretBackend, logical.Storage) {
	t.Helper()

	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}
	adminToken := "AdminToken"
	mockHelper := NewMockapiHelper(ctrl)
	// For the adminKey we always return AdminToken, this lets enforce that the code is correctly using the admin token
	// for the IBM Cloud API calls calls.
	mockHelper.EXPECT().ObtainToken("adminKey").Return(adminToken, nil)
	mockHelper.EXPECT().VerifyToken(gomock.Any(), adminToken).Return(&tokenInfo{Expiry: time.Now().Add(time.Hour)}, nil)
	mockHelper.EXPECT().GetAPIKeyDetails("AdminToken", "adminKey").
		Return(&APIKeyDetailsResponse{ID: "oldID", IAMID: "testIAMID", AccountID: "theAccountID"}, nil)

	// Mock for create of the test role
	mockHelper.EXPECT().CheckServiceIDAccount(adminToken, gomock.Any(), "theAccountID").
		DoAndReturn(func(iamToken, serviceID, accountID string) (*serviceIDv1Response, *logical.Response) {
			if !strutil.StrListContains([]string{"serviceID1"}, serviceID) {
				return nil, logical.ErrorResponse("CheckServiceIDAccount error with %s", serviceID)
			}
			return &serviceIDv1Response{ID: "serviceID1", IAMID: fmt.Sprintf("%s_iam", serviceID)}, nil
		})
	// Mock to fail, simulating a service ID being deleted directly in IBM Cloud or other ID checking failure
	mockHelper.EXPECT().CheckServiceIDAccount(adminToken, gomock.Any(), "theAccountID").
		DoAndReturn(func(iamToken, serviceID, accountID string) (*serviceIDv1Response, *logical.Response) {
			return nil, logical.ErrorResponse("CheckServiceIDAccount error with %s", serviceID)
		})

	b, s := testBackend(t)
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}
	b.apiHelper = mockHelper

	return b, s
}

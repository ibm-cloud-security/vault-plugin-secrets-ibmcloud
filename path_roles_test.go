package ibmcloudsecrets

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// Defaults for verifying response data. If a value is not included here, it must be included in the
// 'expected' map param for a test.
var expectedDefaults = map[string]interface{}{
	ttlField:             int64(0),
	maxTTLField:          int64(0),
	accessGroupIDsField:  []string{},
	serviceIDField:       "",
	cosInstanceGUIDField: "",
}

// Test roles with access groups lists
func TestCRUDHappyPathAccessGroups(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	minCalls := map[string]int{
		"VerifyAccessGroupExists": 4,
	}

	b, s := getMockedBackend(t, ctrl, minCalls)

	roleName := testRole(t)
	boundGroups := []string{"group1", "group2", "group3"}

	testRoleCreate(t, b, s, map[string]interface{}{
		nameField:           roleName,
		accessGroupIDsField: strings.Join(boundGroups, ","),
	})

	testRoleRead(t, b, s, roleName, map[string]interface{}{
		accessGroupIDsField: boundGroups,
	})
	boundGroups = append(boundGroups, "group4")
	testRoleUpdate(t, b, s, map[string]interface{}{
		nameField:           roleName,
		ttlField:            1000,
		maxTTLField:         2000,
		accessGroupIDsField: strings.Join(boundGroups, ","),
	})
	testRoleRead(t, b, s, roleName, map[string]interface{}{
		ttlField:            int64(1000),
		maxTTLField:         int64(2000),
		accessGroupIDsField: boundGroups,
	})
	testRoleDelete(t, b, s, roleName)
}

// Test roles with access groups lists
func TestCRUDHappyPathServiceID(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	minCalls := map[string]int{
		"CheckServiceIDAccount": 2,
	}

	b, s := getMockedBackend(t, ctrl, minCalls)

	roleName := testRole(t)
	boundID := "serviceID1"

	testRoleCreate(t, b, s, map[string]interface{}{
		nameField:      roleName,
		serviceIDField: boundID,
	})

	testRoleRead(t, b, s, roleName, map[string]interface{}{
		serviceIDField: boundID,
	})
	testRoleUpdate(t, b, s, map[string]interface{}{
		nameField:      roleName,
		ttlField:       1000,
		maxTTLField:    2000,
		serviceIDField: "serviceID2",
	})
	testRoleRead(t, b, s, roleName, map[string]interface{}{
		ttlField:       int64(1000),
		maxTTLField:    int64(2000),
		serviceIDField: "serviceID2",
	})
	testRoleDelete(t, b, s, roleName)
}

// Test roles with access groups lists
func TestCRUDHappyPathCOSHMACWithAccessGroups(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	minCalls := map[string]int{
		"VerifyAccessGroupExists": 4,
	}

	b, s := getMockedBackend(t, ctrl, minCalls)

	roleName := testRole(t)
	boundGroups := []string{"group1", "group2", "group3"}
	cosInstanceGUID := "testCOSGUID"

	testRoleCreate(t, b, s, map[string]interface{}{
		nameField:            roleName,
		accessGroupIDsField:  strings.Join(boundGroups, ","),
		cosInstanceGUIDField: cosInstanceGUID,
	})

	testRoleRead(t, b, s, roleName, map[string]interface{}{
		accessGroupIDsField:  boundGroups,
		cosInstanceGUIDField: cosInstanceGUID,
	})
	boundGroups = append(boundGroups, "group4")
	testRoleUpdate(t, b, s, map[string]interface{}{
		nameField:            roleName,
		ttlField:             1000,
		maxTTLField:          2000,
		accessGroupIDsField:  strings.Join(boundGroups, ","),
		cosInstanceGUIDField: cosInstanceGUID,
	})
	testRoleRead(t, b, s, roleName, map[string]interface{}{
		ttlField:             int64(1000),
		maxTTLField:          int64(2000),
		accessGroupIDsField:  boundGroups,
		cosInstanceGUIDField: cosInstanceGUID,
	})
	testRoleDelete(t, b, s, roleName)
}

func TestAccessGroupVerifyError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	minCalls := map[string]int{
		"VerifyAccessGroupExists": 2,
	}

	b, s := getMockedBackend(t, ctrl, minCalls)

	roleName := testRole(t)
	boundGroups := []string{"group1", "problemGroup"}

	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:           roleName,
		accessGroupIDsField: boundGroups,
	},
		[]string{"VerifyAccessGroupExists error with problemGroup"})
}

func TestServiceIDVerifyError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	minCalls := map[string]int{
		"CheckServiceIDAccount": 1,
	}

	b, s := getMockedBackend(t, ctrl, minCalls)

	roleName := testRole(t)

	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:      roleName,
		serviceIDField: "serviceIDNotThere",
	},
		[]string{"CheckServiceIDAccount error with serviceIDNotThere"})
}

func TestCOSInstanceVerifyError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	minCalls := map[string]int{
		"VerifyResourceInstanceExists": 1,
		"VerifyAccessGroupExists":      1,
	}

	b, s := getMockedBackend(t, ctrl, minCalls)

	roleName := testRole(t)
	boundGroups := []string{"group1"}

	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:            roleName,
		accessGroupIDsField:  boundGroups,
		cosInstanceGUIDField: "nonExistentInstance",
	},
		[]string{"VerifyResourceInstanceExists error with nonExistentInstance"})
}

func TestBindingSpecificationErrors(t *testing.T) {
	t.Parallel()

	b, s := testBackend(t)

	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}

	roleName := testRole(t)

	// Test no bindings specified
	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField: roleName,
	},
		[]string{"either a service ID or a non empty access group list are required"})

	// Test both service ID and access group are specified
	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:           roleName,
		serviceIDField:      "s1",
		accessGroupIDsField: []string{"group1"},
	},
		[]string{"either an access group list or service ID should be provided, not both"})

	// Test COS instance specified without access groups
	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:            roleName,
		cosInstanceGUIDField: "s1",
	},
		[]string{"one or more access group must be provided when a Cloud Object Storage instance is provided"})

	// Test when both COS instance and serviceID are specified
	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:            roleName,
		cosInstanceGUIDField: "c1",
		serviceIDField:       "s1",
	},
		[]string{"service IDs cannot be used in roles with Cloud Object Storage instances"})
}

func TestTTLError(t *testing.T) {
	t.Parallel()

	b, s := testBackend(t)

	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}

	roleName := testRole(t)
	boundGroups := []string{"group1"}

	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:           roleName,
		accessGroupIDsField: boundGroups,
		ttlField:            200,
		maxTTLField:         100,
	},
		[]string{"ttl cannot be greater than max_ttl"})
}

func TestAccessGroupLimits(t *testing.T) {
	t.Parallel()

	b, s := testBackend(t)

	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}

	// Test more than the max num of access groups
	//boundGroups := [maxGroupsPerRole + 1]string{}
	boundGroups := make([]string, maxGroupsPerRole+1)
	for index := range boundGroups {
		boundGroups[index] = fmt.Sprintf("group%d", index)
	}

	roleName := testRole(t)
	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:           roleName,
		accessGroupIDsField: boundGroups,
	},
		[]string{fmt.Sprintf("the maximum number of access groups per role is: %d", maxGroupsPerRole)})

	// Test the Public access group
	roleName = testRole(t)
	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField:           roleName,
		accessGroupIDsField: []string{"AccessGroupId-PublicAccess"},
	},
		[]string{"the AccessGroupId-PublicAccess access group is not allowed on roles"})

}

func TestNoConfig(t *testing.T) {
	t.Parallel()

	b, s := testBackend(t)

	roleName := testRole(t)

	testRoleCreateError(t, b, s, map[string]interface{}{
		nameField: roleName,
	},
		[]string{"no API key was set in the configuration"})
}

//-- Utils --
func testRoleCreate(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("roles/%s", d[nameField]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
}

func testRoleUpdate(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("roles/%s", d[nameField]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
}

func testRoleDelete(tb testing.TB, b logical.Backend, s logical.Storage, roleName string) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("roles/%s", roleName),
		Storage:   s,
	})

	if err != nil {
		tb.Fatalf("unable to delete role: %v", err)
	} else if resp != nil {
		if len(resp.Warnings) > 0 {
			tb.Logf("warnings returned from role delete. Warnings:\n %s\n", strings.Join(resp.Warnings, ",\n"))
		}
		if resp.IsError() {
			tb.Fatalf("unable to delete role: %v", resp.Error())
		}
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("roles/%s", roleName),
		Storage:   s,
	})
	if resp != nil || err != nil {
		tb.Fatalf("expected nil response and error, actual:%#v and %#v", resp, err)
	}
}

func testRoleCreateError(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}, expected []string) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("roles/%s", d[nameField]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		tb.Fatalf("expected error containing: %s", strings.Join(expected, ", "))
	}

	for _, str := range expected {
		if !strings.Contains(resp.Error().Error(), str) {
			tb.Fatalf("expected %s to be in error %v", str, resp.Error())
		}
	}
}

func testRoleRead(tb testing.TB, b logical.Backend, s logical.Storage, roleName string, expected map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("roles/%s", roleName),
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
	convertRespTypes(resp.Data)

	if err := checkData(resp, expected, expectedDefaults); err != nil {
		tb.Fatal(err)
	}
}

func checkData(resp *logical.Response, expected map[string]interface{}, expectedDefault map[string]interface{}) error {
	for k, actualVal := range resp.Data {
		expectedVal, ok := expected[k]
		if !ok {
			expectedVal, ok = expectedDefault[k]
			if !ok {
				return fmt.Errorf("must provide expected value for %q for test", k)
			}
		}

		var isEqual bool
		switch actualVal.(type) {
		case []string:
			actual := actualVal.([]string)
			expected, ok := expectedVal.([]string)
			if !ok {
				return fmt.Errorf("%s type mismatch: expected type %T, actual type %T", k, expectedVal, actualVal)
			}
			isEqual = (len(actual) == 0 && len(expected) == 0) ||
				strutil.EquivalentSlices(actual, expected)
		case map[string]string:
			actual := actualVal.(map[string]string)
			expected, ok := expectedVal.(map[string]string)
			if !ok {
				return fmt.Errorf("%s type mismatch: expected type %T, actual type %T", k, expectedVal, actualVal)
			}
			isEqual = (len(actual) == 0 && len(expected) == 0) ||
				reflect.DeepEqual(actualVal, expectedVal)
		default:
			isEqual = actualVal == expectedVal
		}

		if !isEqual {
			return fmt.Errorf("%s mismatch, expected: %v but got %v", k, expectedVal, actualVal)
		}
	}
	// check that the response data has all of the keys in the expected and expectedDefaults maps
	for key := range expected {
		if _, ok := resp.Data[key]; !ok {
			return fmt.Errorf("the response does not have the expected key %s", key)
		}
	}
	for key := range expectedDefault {
		if _, ok := resp.Data[key]; !ok {
			return fmt.Errorf("the response does not have the expected default key %s", key)
		}
	}
	return nil
}

// testRole generates a unique name for a role
func testRole(tb testing.TB) string {
	tb.Helper()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	suffix := fmt.Sprintf("%d", r.Intn(1000000))

	roleName := "v-role-" + suffix

	return roleName
}

/*
	This function configures the mock iamHelper expectations for the test. It then creates a test Backend with
	with the mock, and configures it.

	The minCalls map is used to control the minimum number of times the functions of the iamHelper interface are
	expected to be called. The keys are the function names (e.g. "ObtainToken", "VerifyAccessGroupExists", etc).
	If unspecified 0 is used.
*/
func getMockedBackend(t *testing.T, ctrl *gomock.Controller, minCalls map[string]int) (*ibmCloudSecretBackend, logical.Storage) {
	t.Helper()

	var configData = map[string]interface{}{
		apiKeyField:    "adminKey",
		accountIDField: "theAccountID",
	}

	mockHelper := NewMockapiHelper(ctrl)
	// For the adminKey we always return AdminToken, this lets enforce that the code is correctly using the admin token
	// for the IBM Cloud API calls calls.
	mockHelper.EXPECT().ObtainToken("adminKey").Return("AdminToken", nil)
	mockHelper.EXPECT().VerifyToken(gomock.Any(), "AdminToken").Return(&tokenInfo{Expiry: time.Now().Add(time.Hour)}, nil)
	mockHelper.EXPECT().GetAPIKeyDetails("AdminToken", "adminKey").
		Return(&APIKeyDetailsResponse{ID: "oldID", IAMID: "testIAMID", AccountID: "theAccountID"}, nil)

	mockHelper.EXPECT().VerifyAccessGroupExists("AdminToken", gomock.Any(), "theAccountID").
		MinTimes(minCalls["VerifyAccessGroupExists"]).DoAndReturn(func(iamToken, group, accountID string) *logical.Response {
		if !strutil.StrListContains([]string{"group1", "group2", "group3", "group4"}, group) {
			return logical.ErrorResponse("VerifyAccessGroupExists error with %s", group)
		}
		return nil
	})
	mockHelper.EXPECT().VerifyResourceInstanceExists("AdminToken", gomock.Any()).
		MinTimes(minCalls["VerifyResourceInstanceExists"]).DoAndReturn(func(iamToken, instanceGUID string) *logical.Response {
		if instanceGUID == "nonExistentInstance" {
			return logical.ErrorResponse("VerifyResourceInstanceExists error with %s", instanceGUID)
		}
		return nil
	})
	mockHelper.EXPECT().CheckServiceIDAccount("AdminToken", gomock.Any(), "theAccountID").
		MinTimes(minCalls["CheckServiceIDAccount"]).DoAndReturn(func(iamToken, serviceID, accountID string) (*serviceIDv1Response, *logical.Response) {
		if !strutil.StrListContains([]string{"serviceID1", "serviceID2"}, serviceID) {
			return nil, logical.ErrorResponse("CheckServiceIDAccount error with %s", serviceID)
		}
		return nil, nil
	})

	b, s := testBackend(t)
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}
	b.apiHelper = mockHelper

	return b, s
}

// Utility function to convert response types back to the format that is used as
// input in order to streamline the comparison steps.
func convertRespTypes(data map[string]interface{}) {
	data[ttlField] = int64(data[ttlField].(time.Duration))
	data[maxTTLField] = int64(data[maxTTLField].(time.Duration))
}

package ibmcloudsecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/logical"
)

// A struct to contain information from IBM Cloud tokens that we want to include in Vault token metadata
type tokenInfo struct {
	Subject string
	Expiry  time.Time
}

// IAM API paths
const (
	accessGroupMembers = "/v2/groups/%s/members"
	serviceIDs         = "/v1/serviceids"
	serviceIDDetails   = serviceIDs + "/%s"
	getAccessGroup     = "/v2/groups/%s"
	v1APIKeys          = "/v1/apikeys"
	v1APIKeysID        = v1APIKeys + "/%s"
	v1APIKeyDetails    = "/v1/apikeys/details"
	identityToken      = "/identity/token"
	// IAM OIDC provider paths
	authorizationEndpoint = "/identity/authorize"
	jwksURI               = "/identity/keys"
)

type accountIDDeserializer struct {
	Account string `json:"account_id"`
}

type serviceIDv1Response struct {
	ID      string `json:"id"`
	IAMID   string `json:"iam_id"`
	Account string `json:"account_id"`
}

type AddGroupMembersRequest struct {
	Members []map[string]string `json:"members"`
}

type AddGroupMembersResponse struct {
	Members []AddGroupMembersResponseMembers `json:"members"`
}

type AddGroupMembersResponseMembers struct {
	IAMID  string `json:"iam_id"`
	Status int    `json:"status_code"`
}

type APIKeyV1Response struct {
	APIKey string `json:"apikey"`
	ID     string `json:"id"`
}

type APIKeyDetailsResponse struct {
	ID        string `json:"id"`
	IAMID     string `json:"iam_id"`
	AccountID string `json:"account_id"`
}

type iamHelper interface {
	ObtainToken(apiKey string) (string, error)
	VerifyToken(ctx context.Context, token string) (*tokenInfo, *logical.Response)
	VerifyAccessGroupExists(iamToken, accessGroup, accountID string) *logical.Response
	CheckServiceIDAccount(iamToken, identifier, accountID string) (*serviceIDv1Response, *logical.Response)
	CreateServiceID(iamToken, accountID, roleName string) (iamID, identifier string, err error)
	DeleteServiceID(iamToken, identifier string) error
	AddServiceIDToAccessGroup(iamToken, iamID, group string) error
	CreateAPIKey(iamToken, IAMid, accountID, name, description string) (*APIKeyV1Response, error)
	DeleteAPIKey(iamToken, apiKeyID string) error
	GetAPIKeyDetails(iamToken, apiKeyValue string) (*APIKeyDetailsResponse, error)
	Init(iamEndpoint string)
	Cleanup()
}

type ibmCloudHelper struct {
	providerLock      sync.RWMutex
	provider          *oidc.Provider
	providerCtx       context.Context
	providerCtxCancel context.CancelFunc
	httpClient        *http.Client
	iamEndpoint       string
}

func (h *ibmCloudHelper) Init(iamEndpoint string) {
	h.providerCtx, h.providerCtxCancel = context.WithCancel(context.Background())
	h.httpClient = cleanhttp.DefaultPooledClient()
	h.iamEndpoint = iamEndpoint
}

func (h *ibmCloudHelper) Cleanup() {
	h.providerLock.Lock()
	if h.providerCtxCancel != nil {
		h.providerCtxCancel()
	}
	h.providerLock.Unlock()
}

func (h *ibmCloudHelper) getProvider() *oidc.Provider {
	h.providerLock.RLock()
	unlockFunc := h.providerLock.RUnlock
	defer func() { unlockFunc() }()

	if h.provider != nil {
		return h.provider
	}

	h.providerLock.RUnlock()
	h.providerLock.Lock()
	unlockFunc = h.providerLock.Unlock

	if h.provider != nil {
		return h.provider
	}

	providerCtx := h.providerCtx

	providerConfig := oidc.ProviderConfig{
		IssuerURL: openIDIssuer,
		AuthURL:   h.getURL(authorizationEndpoint),
		TokenURL:  h.getURL(identityToken),
		JWKSURL:   h.getURL(jwksURI),
	}

	provider := providerConfig.NewProvider(providerCtx)
	h.provider = provider
	return provider
}

/**
Obtain an IAM token by way of an API Key
*/
func (h *ibmCloudHelper) ObtainToken(apiKey string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Set("apikey", apiKey)
	data.Set("response_type", "cloud_iam")

	req, err := http.NewRequest(http.MethodPost, h.getURL(identityToken), strings.NewReader(data.Encode()))
	if err != nil {
		return "", errwrap.Wrapf("Error creating obtain token request: {{err}}", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", errwrap.Wrapf("Error obtaining token: {{err}}", err)
	}
	defer closeResponse(resp)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", errwrap.Wrapf("Error decoding the obtained token: {{err}}", err)
	} else if _, ok := result["errorMessage"]; ok {
		return "", fmt.Errorf("error message obtaining token: %s", result["errorMessage"])
	}
	return result["access_token"].(string), nil
}

/**
Verifies an IBM Cloud IAM token. If successful, it will return a tokenInfo
with relevant items contained in the token.
*/
func (h *ibmCloudHelper) VerifyToken(ctx context.Context, token string) (*tokenInfo, *logical.Response) {
	// verify the token
	provider := h.getProvider()

	oidcConfig := &oidc.Config{
		SkipClientIDCheck: true,
	}
	verifier := provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, logical.ErrorResponse("an error occurred verifying the token %s", err)
	}

	return &tokenInfo{
		Subject: idToken.Subject,
		Expiry:  idToken.Expiry,
	}, nil

}

func (h *ibmCloudHelper) VerifyAccessGroupExists(iamToken, accessGroup, accountID string) *logical.Response {
	r, err := http.NewRequest(http.MethodGet, h.getURL(getAccessGroup, accessGroup), nil)
	if err != nil {
		return logical.ErrorResponse("failed creating http request: %s", err)

	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return logical.ErrorResponse("error with http request: %s", err)
	}

	if httpStatus == 404 {
		return logical.ErrorResponse("the access group %s does not exist", accessGroup)
	}
	if httpStatus != 200 {
		return logical.ErrorResponse("unexpected http status code from access group API: %v with response %v", httpStatus, string(body))
	}
	groupInfo := new(accountIDDeserializer)

	if err := json.Unmarshal(body, &groupInfo); err != nil {
		return logical.ErrorResponse("error reading access group API response: %s", err)
	}

	if accountID != groupInfo.Account {
		return logical.ErrorResponse("the access group %s, was created in account %s which does not match the configured account %s", accessGroup, groupInfo.Account, accountID)
	}

	return nil
}

func (h *ibmCloudHelper) CreateServiceID(iamToken, accountID, roleName string) (iamID, identifier string, err error) {
	requestBody, err := json.Marshal(map[string]string{
		"name":        fmt.Sprintf("vault-generated-%s", roleName),
		"account_id":  accountID,
		"description": fmt.Sprintf("Generated by Vault's secret engine for IBM Cloud credentials using Vault role %s.", roleName),
	})
	if err != nil {
		return "", "", errwrap.Wrapf("failed marshalling the request for creating a service ID: {{err}}", err)
	}

	r, err := http.NewRequest(http.MethodPost, h.getURL(serviceIDs), bytes.NewBuffer(requestBody))
	if err != nil {
		return "", "", errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return "", "", err
	}

	if httpStatus != 201 {
		return "", "", fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	idInfo := new(serviceIDv1Response)

	if err := json.Unmarshal(body, &idInfo); err != nil {
		return "", "", err
	}

	return idInfo.IAMID, idInfo.ID, nil
}

// Checks the existence of a service ID and verifies that it is created in the passed in account.
// Returns the serviceIDv1Response struct with service ID information if successful, else returns an error logical.Response
func (h *ibmCloudHelper) CheckServiceIDAccount(iamToken, identifier, accountID string) (*serviceIDv1Response, *logical.Response) {
	r, err := http.NewRequest(http.MethodGet, h.getURL(serviceIDDetails, identifier), nil)
	if err != nil {
		return nil, logical.ErrorResponse("failed creating http request: %s", err)

	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return nil, logical.ErrorResponse("error with http request: %s", err)
	}
	if httpStatus == 404 {
		return nil, logical.ErrorResponse("service ID %s does not exist", identifier)
	}
	if httpStatus != 200 {
		return nil, logical.ErrorResponse("unexpected http status code: %v with response %v", httpStatus, string(body))

	}
	idInfo := new(serviceIDv1Response)

	if err := json.Unmarshal(body, &idInfo); err != nil {
		return nil, logical.ErrorResponse("error reading API response: %s", err)
	}

	if accountID != idInfo.Account {
		return nil, logical.ErrorResponse("service ID account %s does not match the configured account %s", idInfo.Account, accountID)
	}

	return idInfo, nil
}

func (h *ibmCloudHelper) AddServiceIDToAccessGroup(iamToken string, iamID string, group string) error {
	reqBody := new(AddGroupMembersRequest)
	reqBody.Members = []map[string]string{{"iam_id": iamID, "type": "service"}}
	requestBody, err := json.Marshal(reqBody)

	if err != nil {
		return errwrap.Wrapf("failed marshalling the request for adding a serviceID to access group: {{err}}", err)
	}

	r, err := http.NewRequest(http.MethodPut, h.getURL(accessGroupMembers, group), bytes.NewBuffer(requestBody))
	if err != nil {
		return errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return err
	}

	if httpStatus != 207 {
		return fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	resp := new(AddGroupMembersResponse)

	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	if len(resp.Members) == 0 {
		return fmt.Errorf("no member sections found in response %v", string(body))
	}
	if resp.Members[0].Status != 200 {
		return fmt.Errorf("error adding member to the access group. http status code: %v with response %v", resp.Members[0].Status, string(body))
	}

	return nil
}

func (h *ibmCloudHelper) CreateAPIKey(iamToken, IAMid, accountID, name, description string) (*APIKeyV1Response, error) {
	requestBody, err := json.Marshal(map[string]interface{}{
		"name":        name,
		"iam_id":      IAMid,
		"account_id":  accountID,
		"description": description,
		"store_value": false,
	})
	if err != nil {
		return nil, errwrap.Wrapf("failed marshalling the request for creating a service ID: {{err}}", err)
	}

	r, err := http.NewRequest(http.MethodPost, h.getURL(v1APIKeys), bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return nil, err
	}

	if httpStatus != 201 {
		return nil, fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	keyInfo := new(APIKeyV1Response)

	if err := json.Unmarshal(body, &keyInfo); err != nil {
		return nil, err
	}

	if len(keyInfo.APIKey) == 0 {
		return nil, fmt.Errorf("an empty API key was returned with code %v and response %v", httpStatus, string(body))
	}
	if len(keyInfo.ID) == 0 {
		return nil, fmt.Errorf("API key with an empty ID was returned with code %v and response %v", httpStatus, string(body))
	}
	return keyInfo, nil
}

func (h *ibmCloudHelper) DeleteAPIKey(iamToken, apiKeyID string) error {
	r, err := http.NewRequest(http.MethodDelete, h.getURL(v1APIKeysID, apiKeyID), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return err
	}

	if httpStatus != 204 {
		return fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	return nil
}

func (h *ibmCloudHelper) GetAPIKeyDetails(iamToken, apiKeyValue string) (*APIKeyDetailsResponse, error) {
	r, err := http.NewRequest(http.MethodGet, h.getURL(v1APIKeyDetails), nil)
	if err != nil {
		return nil, errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("IAM-Apikey", apiKeyValue)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return nil, err
	}

	keyDetails := new(APIKeyDetailsResponse)

	if err := json.Unmarshal(body, &keyDetails); err != nil {
		return nil, err
	}

	if httpStatus != 200 {
		return nil, fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	return keyDetails, nil
}

func (h *ibmCloudHelper) DeleteServiceID(iamToken, identifier string) error {
	r, err := http.NewRequest(http.MethodDelete, h.getURL(serviceIDDetails, identifier), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return err
	}

	if httpStatus != 204 {
		return fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	return nil
}

func (h *ibmCloudHelper) getURL(path string, pathReplacements ...string) string {
	pathSubs := make([]interface{}, len(pathReplacements))
	for i, v := range pathReplacements {
		pathSubs[i] = v
	}
	return fmt.Sprintf("%s%s", h.iamEndpoint, fmt.Sprintf(path, pathSubs...))
}

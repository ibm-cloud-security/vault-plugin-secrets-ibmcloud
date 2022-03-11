package ibmcloudsecrets

const (
	iamEndpointFieldDefault = "https://iam.cloud.ibm.com"
	openIDIssuer            = "https://iam.cloud.ibm.com/identity"
)

//Number of minutes to renew the admin token before expiration
const (
	adminTokenRenewBeforeExpirationMinutes = 5
	maxGroupsPerRole                       = 10
)

const (
	accountIDField       = "account_id"
	roleField            = "role"
	apiKeyField          = "api_key"
	redacted             = "<redacted>"
	nameField            = "name"
	accessGroupIDsField  = "access_group_ids"
	ttlField             = "ttl"
	maxTTLField          = "max_ttl"
	secretTypeKey        = "service_id_key"
	rolesStoragePath     = "roles"
	roleNameField        = "role_name"
	roleBindingHashField = "role_binding_hash"
	serviceIDField       = "service_id"
	apiKeyID             = "api_key_id"
)

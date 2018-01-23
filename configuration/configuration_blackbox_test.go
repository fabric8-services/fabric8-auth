package configuration_test

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"net/http"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	varTokenPrivateKey = "token.privatekey"
)

var reqLong *goa.RequestData
var reqShort *goa.RequestData
var config *configuration.ConfigurationData

func TestMain(m *testing.M) {
	resetConfiguration()

	reqLong = &goa.RequestData{
		Request: &http.Request{Host: "api.service.domain.org"},
	}
	reqShort = &goa.RequestData{
		Request: &http.Request{Host: "api.domain.org"},
	}
	os.Exit(m.Run())
}

func resetConfiguration() {
	var err error

	// calling NewConfigurationData("") is same as GetConfigurationData()
	config, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

func TestGetKeycloakEndpointSetByUrlEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	env := os.Getenv("AUTH_KEYCLOAK_URL")
	defer func() {
		os.Setenv("AUTH_KEYCLOAK_URL", env)
		resetConfiguration()
	}()

	os.Setenv("AUTH_KEYCLOAK_URL", "http://xyz.io")
	resetConfiguration()

	url, err := config.GetKeycloakEndpointAuth(reqLong)
	require.Nil(t, err)
	require.Equal(t, "http://xyz.io/auth/realms/"+config.GetKeycloakRealm()+"/protocol/openid-connect/auth", url)

	url, err = config.GetKeycloakEndpointLogout(reqLong)
	require.Nil(t, err)
	require.Equal(t, "http://xyz.io/auth/realms/"+config.GetKeycloakRealm()+"/protocol/openid-connect/logout", url)

	url, err = config.GetKeycloakEndpointToken(reqLong)
	require.Nil(t, err)
	require.Equal(t, "http://xyz.io/auth/realms/"+config.GetKeycloakRealm()+"/protocol/openid-connect/token", url)

	url, err = config.GetKeycloakEndpointUserInfo(reqLong)
	require.Nil(t, err)
	require.Equal(t, "http://xyz.io/auth/realms/"+config.GetKeycloakRealm()+"/protocol/openid-connect/userinfo", url)

	url, err = config.GetKeycloakEndpointAuthzResourceset(reqLong)
	require.Nil(t, err)
	require.Equal(t, "http://xyz.io/auth/realms/"+config.GetKeycloakRealm()+"/authz/protection/resource_set", url)

	url, err = config.GetKeycloakEndpointClients(reqLong)
	require.Nil(t, err)
	require.Equal(t, "http://xyz.io/auth/admin/realms/"+config.GetKeycloakRealm()+"/clients", url)

	url, err = config.GetKeycloakEndpointEntitlement(reqLong)
	require.Nil(t, err)
	require.Equal(t, "http://xyz.io/auth/realms/"+config.GetKeycloakRealm()+"/authz/entitlement/fabric8-online-platform", url)
}

func TestGetKeycloakEndpointAdminDevModeOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/admin/realms/"+config.GetKeycloakRealm(), config.GetKeycloakEndpointAdmin)
}

func TestGetKeycloakEndpointAdminSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_ADMIN", config.GetKeycloakEndpointAdmin)
}

func TestGetKeycloakEndpointAuthzResourcesetDevModeOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/realms/"+config.GetKeycloakRealm()+"/authz/protection/resource_set", config.GetKeycloakEndpointAuthzResourceset)
}

func TestGetKeycloakEndpointAuthzResourcesetSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_AUTHZ_RESOURCESET", config.GetKeycloakEndpointAuthzResourceset)
}

func TestGetKeycloakEndpointClientsDevModeOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/admin/realms/"+config.GetKeycloakRealm()+"/clients", config.GetKeycloakEndpointClients)
}

func TestGetKeycloakEndpoinClientsSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_CLIENTS", config.GetKeycloakEndpointClients)
}

func TestGetKeycloakEndpointAuthDevModeOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/realms/"+config.GetKeycloakRealm()+"/protocol/openid-connect/auth", config.GetKeycloakEndpointAuth)
}

func TestGetKeycloakEndpointAuthSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_AUTH", config.GetKeycloakEndpointAuth)
}

func TestGetKeycloakEndpointLogoutDevModeOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/realms/"+config.GetKeycloakRealm()+"/protocol/openid-connect/logout", config.GetKeycloakEndpointLogout)
}

func TestGetKeycloakEndpointLogoutSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_LOGOUT", config.GetKeycloakEndpointLogout)
}

func TestGetKeycloakEndpointTokenOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/realms/"+config.GetKeycloakRealm()+"/protocol/openid-connect/token", config.GetKeycloakEndpointToken)
}

func TestGetKeycloakEndpointTokenSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_TOKEN", config.GetKeycloakEndpointToken)
}

func TestGetKeycloakEndpointUserInfoOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/realms/"+config.GetKeycloakRealm()+"/protocol/openid-connect/userinfo", config.GetKeycloakEndpointUserInfo)
}

func TestGetKeycloakEndpointLinkIDPOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	sampleID := "1234"
	idp := "openshift-v3"
	expectedEndpoint := config.GetKeycloakDevModeURL() + "/auth/admin/realms/" + config.GetKeycloakRealm() + "/users/" + sampleID + "/federated-identity/" + idp
	url, err := config.GetKeycloakEndpointLinkIDP(reqLong, sampleID, idp)
	assert.Nil(t, err)
	// In dev mode it's always the defualt value regardless of the request
	assert.Equal(t, expectedEndpoint, url)

	url, err = config.GetKeycloakEndpointLinkIDP(reqShort, sampleID, idp)
	assert.Nil(t, err)
	// In dev mode it's always the defualt value regardless of the request
	assert.Equal(t, expectedEndpoint, url)
}

func TestGetKeycloakEndpointUsersOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/admin/realms/"+config.GetKeycloakRealm()+"/users", config.GetKeycloakEndpointUsers)
}

func TestGetKeycloakEndpointUserInfoSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_USERINFO", config.GetKeycloakEndpointUserInfo)
}

func TestGetKeycloakEndpointEntitlementOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/realms/"+config.GetKeycloakRealm()+"/authz/entitlement/fabric8-online-platform", config.GetKeycloakEndpointEntitlement)
}

func TestGetKeycloakEndpointEntitlementSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_ENTITLEMENT", config.GetKeycloakEndpointEntitlement)
}

func TestGetKeycloakEndpointBrokerOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/realms/"+config.GetKeycloakRealm()+"/broker", config.GetKeycloakEndpointBroker)
}

func TestGetKeycloakEndpointBrokerSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_BROKER", config.GetKeycloakEndpointBroker)
}

func TestGetKeycloakUserInfoEndpointOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	t.Parallel()
	checkGetKeycloakEndpointOK(t, config.GetKeycloakDevModeURL()+"/auth/realms/"+config.GetKeycloakRealm()+"/account", config.GetKeycloakAccountEndpoint)
}

func TestGetKeycloakUserInfoEndpointOKrSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	checkGetKeycloakEndpointSetByEnvVaribaleOK(t, "AUTH_KEYCLOAK_ENDPOINT_ACCOUNT", config.GetKeycloakAccountEndpoint)
}

func TestGetWITURLNotDevModeOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	existingWITprefix := os.Getenv("AUTH_WIT_DOMAIN_PREFIX")
	existingDevMode := os.Getenv("AUTH_DEVELOPER_MODE_ENABLED")
	defer func() {
		os.Setenv("AUTH_WIT_DOMAIN_PREFIX", existingWITprefix)
		os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", existingDevMode)
		resetConfiguration()
	}()

	os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", "false")

	// Ensure that what we set as env variable is actually what we get
	computedWITURL, err := config.GetWITURL(reqShort)
	assert.Nil(t, err)
	assert.Equal(t, "http://api.domain.org", computedWITURL)

	os.Setenv("AUTH_WIT_DOMAIN_PREFIX", "myauthsubdomain")
	computedWITURL, err = config.GetWITURL(reqLong)
	assert.Nil(t, err)
	assert.Equal(t, "http://myauthsubdomain.service.domain.org", computedWITURL)
}

func TestGetWITURLDevModeOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	existingWITprefix := os.Getenv("AUTH_WIT_DOMAIN_PREFIX")
	existingDevMode := os.Getenv("AUTH_DEVELOPER_MODE_ENABLED")
	defer func() {
		os.Setenv("AUTH_WIT_DOMAIN_PREFIX", existingWITprefix)
		os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", existingDevMode)
		resetConfiguration()
	}()

	os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", "true")

	// Ensure that what we set as env variable is actually what we get
	computedWITURL, err := config.GetWITURL(reqShort)
	assert.Nil(t, err)
	assert.Equal(t, "http://localhost:8080", computedWITURL)
}

func TestGetWITURLSetViaEnvVarOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	existingWITURL := os.Getenv("AUTH_WIT_URL")
	defer func() {
		if existingWITURL != "" {
			os.Setenv("AUTH_WIT_URL", existingWITURL)
		} else {
			os.Unsetenv("AUTH_WIT_URL")
		}
		resetConfiguration()
	}()

	os.Setenv("AUTH_WIT_URL", "https://new.wit.url")

	// Ensure that what we set as env variable is actually what we get
	computedWITURL, err := config.GetWITURL(reqShort)
	assert.Nil(t, err)
	assert.Equal(t, "https://new.wit.url", computedWITURL)
}

func checkGetKeycloakEndpointOK(t *testing.T, expectedEndpoint string, getEndpoint func(req *goa.RequestData) (string, error)) {
	url, err := getEndpoint(reqLong)
	assert.Nil(t, err)
	// In dev mode it's always the defualt value regardless of the request
	assert.Equal(t, expectedEndpoint, url)

	url, err = getEndpoint(reqShort)
	assert.Nil(t, err)
	// In dev mode it's always the defualt value regardless of the request
	assert.Equal(t, expectedEndpoint, url)
}

func TestGetTokenPrivateKeyFromConfigFile(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	envKey := generateEnvKey(varTokenPrivateKey)
	realEnvValue := os.Getenv(envKey) // could be "" as well.

	os.Unsetenv(envKey)
	defer func() {
		os.Setenv(envKey, realEnvValue)
		resetConfiguration()
	}()

	resetConfiguration()
	// env variable NOT set, so we check with config.yaml's value

	viperValue, kid := config.GetServiceAccountPrivateKey()
	assert.NotEqual(t, "", kid)
	require.NotNil(t, viperValue)

	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(viperValue)
	require.Nil(t, err)
	assert.NotNil(t, parsedKey)
}

func TestGetMaxHeaderSizeUsingDefaults(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	viperValue := config.GetHeaderMaxLength()
	require.NotNil(t, viperValue)
	assert.Equal(t, int64(5000), viperValue)
}

func TestGetMaxHeaderSizeSetByEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	envName := "AUTH_HEADER_MAXLENGTH"
	envValue := time.Now().Unix()
	env := os.Getenv(envName)
	defer func() {
		os.Setenv(envName, env)
		resetConfiguration()
	}()

	os.Setenv(envName, strconv.FormatInt(envValue, 10))
	resetConfiguration()

	viperValue := config.GetHeaderMaxLength()
	require.NotNil(t, viperValue)
	assert.Equal(t, envValue, viperValue)
}

func TestLoadDefaultServiceAccountConfiguration(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	accounts := config.GetServiceAccounts()
	checkServiceAccountConfiguration(t, accounts)
}

func TestLoadServiceAccountConfigurationFromFile(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	saConfig, err := configuration.NewConfigurationData("", "./conf-files/service-account-secrets.conf", "")
	require.Nil(t, err)
	accounts := saConfig.GetServiceAccounts()
	checkServiceAccountConfiguration(t, accounts)
}

func TestGetPublicClientID(t *testing.T) {
	require.Equal(t, "740650a2-9c44-4db5-b067-a3d1b2cd2d01", config.GetPublicOauthClientID())
}

func checkServiceAccountConfiguration(t *testing.T, accounts map[string]configuration.ServiceAccount) {
	checkServiceAccount(t, accounts, configuration.ServiceAccount{
		ID:      "5dec5fdb-09e3-4453-b73f-5c828832b28e",
		Name:    "fabric8-wit",
		Secrets: []string{"$2a$04$nI7z7Re4pbx.V5vwm14n5.velhB.nbMgxdZ0vSomWVxcct34zbH9e"}})
	checkServiceAccount(t, accounts, configuration.ServiceAccount{
		ID:      "c211f1bd-17a7-4f8c-9f80-0917d167889d",
		Name:    "fabric8-tenant",
		Secrets: []string{"$2a$04$ynqM/syKMYowMIn5cyqHuevWnfzIQqtyY4m.61B02qltY5SOyGIOe", "$2a$04$sbC/AfW2c33hv8orGA.1D.LXa/.IY76VWhsfqxCVhrhFkDfL0/XGK"}})
}

func checkServiceAccount(t *testing.T, accounts map[string]configuration.ServiceAccount, expected configuration.ServiceAccount) {
	assert.Contains(t, accounts, expected.ID)
	assert.Equal(t, expected, accounts[expected.ID])
}

func TestLoadDefaultClusterConfiguration(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	clusters := config.GetOSOClusters()
	checkClusterConfiguration(t, clusters)
}

func TestLoadClusterConfigurationFromFile(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	clusterConfig, err := configuration.NewConfigurationData("", "", "./conf-files/oso-clusters.conf")
	require.Nil(t, err)
	clusters := clusterConfig.GetOSOClusters()
	checkClusterConfiguration(t, clusters)
}

func checkClusterConfiguration(t *testing.T, clusters map[string]configuration.OSOCluster) {
	checkCluster(t, clusters, configuration.OSOCluster{
		Name:                   "us-east-2",
		APIURL:                 "https://api.starter-us-east-2.openshift.com",
		AppDNS:                 "8a09.starter-us-east-2.openshiftapps.com",
		ServiceAccountToken:    "fX0nH3d68LQ6SK5wBE6QeKJ6X8AZGVQO3dGQZZETakhmgmWAqr2KDFXE65KUwBO69aWoq",
		ServiceAccountUsername: "dsaas",
		TokenProviderID:        "f867ac10-5e05-4359-a0c6-b855ece59090",
		AuthClientID:           "autheast2",
		AuthClientSecret:       "autheast2secret",
		AuthClientDefaultScope: "user:full",
	})
	checkCluster(t, clusters, configuration.OSOCluster{
		Name:                   "us-east-2a",
		APIURL:                 "https://api.starter-us-east-2a.openshift.com",
		AppDNS:                 "1234.starter-us-east-2a.openshiftapps.com",
		ServiceAccountToken:    "ak61T6RSAacWFruh1vZP8cyUOBtQ3Chv1rdOBddSuc9nZ2wEcs81DHXRO55NpIpVQ8uiH",
		ServiceAccountUsername: "dsaas",
		TokenProviderID:        "886c7ea3-ef97-443d-b345-de94b94bb65d",
		AuthClientID:           "autheast2a",
		AuthClientSecret:       "autheast2asecret",
		AuthClientDefaultScope: "user:full",
	})
}

func checkCluster(t *testing.T, clusters map[string]configuration.OSOCluster, expected configuration.OSOCluster) {
	require.Contains(t, clusters, expected.APIURL)
	require.Equal(t, expected, clusters[expected.APIURL])
	_, err := uuid.FromString(clusters[expected.APIURL].TokenProviderID)
	require.Nil(t, err)
}

func TestIsTLSInsecureSkipVerifySetToFalse(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	require.False(t, config.IsTLSInsecureSkipVerify())
}

func generateEnvKey(yamlKey string) string {
	return "AUTH_" + strings.ToUpper(strings.Replace(yamlKey, ".", "_", -1))
}

func checkGetKeycloakEndpointSetByEnvVaribaleOK(t *testing.T, envName string, getEndpoint func(req *goa.RequestData) (string, error)) {
	envValue := uuid.NewV4().String()
	env := os.Getenv(envName)
	defer func() {
		os.Setenv(envName, env)
		resetConfiguration()
	}()

	os.Setenv(envName, envValue)
	resetConfiguration()

	url, err := getEndpoint(reqLong)
	require.Nil(t, err)
	require.Equal(t, envValue, url)

	url, err = getEndpoint(reqShort)
	require.Nil(t, err)
	require.Equal(t, envValue, url)
}

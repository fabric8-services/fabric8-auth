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
	varTokenPublicKey           = "token.publickey"
	varTokenPrivateKey          = "token.privatekey"
	defaultConfigFilePath       = "../config.yaml"
	defaultValuesConfigFilePath = "" // when the code defaults are to be used, the path to config file is ""
)

var reqLong *goa.RequestData
var reqShort *goa.RequestData
var config *configuration.ConfigurationData

func TestMain(m *testing.M) {
	resetConfiguration(defaultConfigFilePath)

	reqLong = &goa.RequestData{
		Request: &http.Request{Host: "api.service.domain.org"},
	}
	reqShort = &goa.RequestData{
		Request: &http.Request{Host: "api.domain.org"},
	}
	os.Exit(m.Run())
}

func resetConfiguration(configPath string) {
	var err error

	// calling NewConfigurationData("") is same as GetConfigurationData()
	config, err = configuration.NewConfigurationData(configPath)
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

func TestGetKeycloakEndpointSetByUrlEnvVaribaleOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	env := os.Getenv("AUTH_KEYCLOAK_URL")
	defer func() {
		os.Setenv("AUTH_KEYCLOAK_URL", env)
		resetConfiguration(defaultValuesConfigFilePath)
	}()

	os.Setenv("AUTH_KEYCLOAK_URL", "http://xyz.io")
	resetConfiguration(defaultValuesConfigFilePath)

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
		resetConfiguration(defaultValuesConfigFilePath)
		os.Setenv("AUTH_WIT_DOMAIN_PREFIX", existingWITprefix)
		os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", existingDevMode)
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
		resetConfiguration(defaultValuesConfigFilePath)
		os.Setenv("AUTH_WIT_DOMAIN_PREFIX", existingWITprefix)
		os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", existingDevMode)
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
		resetConfiguration(defaultValuesConfigFilePath)
		if existingWITURL != "" {
			os.Setenv("AUTH_WIT_URL", existingWITURL)
		} else {
			os.Unsetenv("AUTH_WIT_URL")
		}
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
		resetConfiguration(defaultValuesConfigFilePath)
	}()

	resetConfiguration(defaultConfigFilePath)
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
		resetConfiguration(defaultValuesConfigFilePath)
	}()

	os.Setenv(envName, strconv.FormatInt(envValue, 10))
	resetConfiguration(defaultValuesConfigFilePath)

	viperValue := config.GetHeaderMaxLength()
	require.NotNil(t, viperValue)
	assert.Equal(t, envValue, viperValue)
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
		resetConfiguration(defaultValuesConfigFilePath)
	}()

	os.Setenv(envName, envValue)
	resetConfiguration(defaultValuesConfigFilePath)

	url, err := getEndpoint(reqLong)
	require.Nil(t, err)
	require.Equal(t, envValue, url)

	url, err = getEndpoint(reqShort)
	require.Nil(t, err)
	require.Equal(t, envValue, url)
}

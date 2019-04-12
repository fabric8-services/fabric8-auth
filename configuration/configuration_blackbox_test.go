package configuration_test

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
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

func TestGetWITURLNotDevModeOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	existingWITprefix := os.Getenv("AUTH_WIT_DOMAIN_PREFIX")
	existingDevMode := os.Getenv("AUTH_DEVELOPER_MODE_ENABLED")
	existingWITURL := os.Getenv("AUTH_WIT_URL")
	existingAuthURL := os.Getenv("AUTH_AUTH_URL")
	defer func() {
		os.Setenv("AUTH_WIT_DOMAIN_PREFIX", existingWITprefix)
		os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", existingDevMode)
		os.Setenv("AUTH_WIT_URL", existingWITURL)
		os.Setenv("AUTH_AUTH_URL", existingAuthURL)
		resetConfiguration()
	}()

	// Default in dev mode
	os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", "true")
	os.Unsetenv("AUTH_WIT_URL")
	resetConfiguration()
	computedWITURL, err := config.GetWITURL()
	assert.Nil(t, err)
	assert.Equal(t, "http://localhost:8080", computedWITURL)

	// Constructed from Auth URL
	os.Setenv("AUTH_DEVELOPER_MODE_ENABLED", "false")
	os.Setenv("AUTH_AUTH_URL", "https://auth.forwiturltest.io")
	resetConfiguration()
	computedWITURL, err = config.GetWITURL()
	assert.Nil(t, err)
	assert.Equal(t, "https://api.forwiturltest.io", computedWITURL)

	// Explicitly set via AUTH_WIT_URL env var
	os.Setenv("AUTH_WIT_URL", "https://api.some.wit.io")
	resetConfiguration()
	computedWITURL, err = config.GetWITURL()
	assert.Nil(t, err)
	assert.Equal(t, "https://api.some.wit.io", computedWITURL)
}

func TestGetEnvironmentOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	constAuthEnvironment := "AUTH_ENVIRONMENT"
	constAuthSentryDSN := "AUTH_SENTRY_DSN"
	constLocalEnv := "local"

	existingEnvironmentName := os.Getenv(constAuthEnvironment)
	existingSentryDSN := os.Getenv(constAuthSentryDSN)
	defer func() {
		os.Setenv(constAuthEnvironment, existingEnvironmentName)
		os.Setenv(constAuthSentryDSN, existingSentryDSN)
		resetConfiguration()
	}()

	os.Unsetenv(constAuthEnvironment)
	assert.Equal(t, constLocalEnv, config.GetEnvironment())

	// Test auth service URL

	// Environment not set
	saConfig, err := configuration.GetConfigurationData()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost", saConfig.GetAuthServiceURL())
	assert.Contains(t, saConfig.DefaultConfigurationError().Error(), "environment is expected to be set to 'production' or 'prod-preview'")

	// Environment set to some unknown value
	os.Setenv(constAuthEnvironment, "somethingelse")
	saConfig, err = configuration.GetConfigurationData()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost", saConfig.GetAuthServiceURL())
	assert.Contains(t, saConfig.DefaultConfigurationError().Error(), "environment is expected to be set to 'production' or 'prod-preview'")

	// Environment set to prod-preview
	os.Setenv(constAuthEnvironment, "prod-preview")
	saConfig, err = configuration.GetConfigurationData()
	require.NoError(t, err)
	assert.Equal(t, "prod-preview", saConfig.GetEnvironment())
	assert.Equal(t, "https://auth.prod-preview.openshift.io", saConfig.GetAuthServiceURL())
	assert.NotContains(t, saConfig.DefaultConfigurationError().Error(), "environment is expected to be set to 'production' or 'prod-preview'")

	// Environment set to production
	os.Setenv(constAuthEnvironment, "production")
	saConfig, err = configuration.GetConfigurationData()
	require.NoError(t, err)
	assert.Equal(t, "production", saConfig.GetEnvironment())
	assert.Equal(t, "https://auth.openshift.io", saConfig.GetAuthServiceURL())
	assert.NotContains(t, saConfig.DefaultConfigurationError().Error(), "environment is expected to be set to 'production' or 'prod-preview'")
}

func TestNotificationServiceURL(t *testing.T) {
	checkURLValidation(t, "AUTH_NOTIFICATION_SERVICEURL", "notification service")
}

func TestOSORegistrationAppURL(t *testing.T) {
	checkURLValidation(t, "AUTH_OSO_REGAPP_SERVICEURL", "OSO Reg App")
}

func checkURLValidation(t *testing.T, envName, serviceName string) {
	resource.Require(t, resource.UnitTest)

	existingEnvironment := os.Getenv(envName)
	defer func() {
		os.Setenv(envName, existingEnvironment)
		resetConfiguration()
	}()

	// URL not set: use default
	os.Unsetenv(envName)
	saConfig, err := configuration.GetConfigurationData()
	require.NoError(t, err)
	assert.NotContains(t, saConfig.DefaultConfigurationError().Error(), fmt.Sprintf("%s url is empty", serviceName))

	// URL is invalid
	os.Setenv(envName, "%")
	saConfig, err = configuration.GetConfigurationData()
	require.NoError(t, err)
	assert.Contains(t, saConfig.DefaultConfigurationError().Error(), fmt.Sprintf("invalid %s url: %s", serviceName, "parse %: invalid URL escape \"%\""))

	// URL is valid
	os.Setenv(envName, "https://openshift.io")
	saConfig, err = configuration.GetConfigurationData()
	require.NoError(t, err)
	assert.NotContains(t, saConfig.DefaultConfigurationError().Error(), "serviceName")
}

func TestGetSentryDSNOK(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	constSentryDSN := "AUTH_SENTRY_DSN"
	existingDSN := os.Getenv(constSentryDSN)
	defer func() {
		os.Setenv(constSentryDSN, existingDSN)
		resetConfiguration()
	}()

	os.Unsetenv(constSentryDSN)
	assert.Equal(t, "", config.GetSentryDSN())

	os.Setenv(constSentryDSN, "something")
	assert.Equal(t, "something", config.GetSentryDSN())
}

func checkGetKeycloakEndpointOK(t *testing.T, expectedEndpoint string, getEndpoint func(req *goa.RequestData) (string, error)) {
	url, err := getEndpoint(reqLong)
	assert.Nil(t, err)
	// In dev mode it's always the default value regardless of the request
	assert.Equal(t, expectedEndpoint, url)

	url, err = getEndpoint(reqShort)
	assert.Nil(t, err)
	// In dev mode it's always the default value regardless of the request
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

func TestGetMaxHeaderSizeSetByEnvVariableOK(t *testing.T) {
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

	saConfig, err := configuration.NewConfigurationData("", "./conf-files/service-account-secrets.conf")
	require.Nil(t, err)
	accounts := saConfig.GetServiceAccounts()
	checkServiceAccountConfiguration(t, accounts)
}

func TestLoadServiceAccountConfigurationWithMissingExpectedSAReportsError(t *testing.T) {
	resource.Require(t, resource.UnitTest)

	saConfig, err := configuration.NewConfigurationData("", "./conf-files/tests/service-account-missing-expected.conf")
	require.Nil(t, err)
	assert.Contains(t, saConfig.DefaultConfigurationError().Error(), "service account name is empty in service account config")
	assert.Contains(t, saConfig.DefaultConfigurationError().Error(), "test-service service account ID is empty in service account config;")
	assert.Contains(t, saConfig.DefaultConfigurationError().Error(), "test-service service account secret array is empty in service account config;")
	assert.Contains(t, saConfig.DefaultConfigurationError().Error(), "some expected service accounts are missing in service account config;")
}

func TestGetPublicClientID(t *testing.T) {
	require.Equal(t, "740650a2-9c44-4db5-b067-a3d1b2cd2d01", config.GetPublicOAuthClientID())
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

func TestExpiresIn(t *testing.T) {
	checkExpiresIn(t, "AUTH_USERACCOUNT_TOKEN_ACCESS_EXPIRESIN", "too short lifespan of access tokens")
	checkExpiresIn(t, "AUTH_USERACCOUNT_TOKEN_REFRESH_EXPIRESIN", "too short lifespan of refresh tokens")
}

func checkExpiresIn(t *testing.T, envVarName, expectedErrorMessage string) {
	resource.Require(t, resource.UnitTest)

	tokenExpiresIn := os.Getenv(envVarName)
	defer func() {
		os.Setenv(envVarName, tokenExpiresIn)
		resetConfiguration()
	}()

	// There should be an error message if expiresIn is less than 3 minutes
	os.Setenv(envVarName, "179")
	resetConfiguration()

	assert.Contains(t, config.DefaultConfigurationError().Error(), expectedErrorMessage)

	// No error message if expiresIn is >= 3 minutes
	os.Setenv(envVarName, "180")
	resetConfiguration()

	assert.NotContains(t, config.DefaultConfigurationError().Error(), expectedErrorMessage)
}

func generateEnvKey(yamlKey string) string {
	return "AUTH_" + strings.ToUpper(strings.Replace(yamlKey, ".", "_", -1))
}

func checkGetKeycloakEndpointSetByEnvVariableOK(t *testing.T, envName string, getEndpoint func(req *goa.RequestData) (string, error)) {
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

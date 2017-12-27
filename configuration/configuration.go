package configuration

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/goadesign/goa"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// String returns the current configuration as a string
func (c *ConfigurationData) String() string {
	allSettings := c.v.AllSettings()
	y, err := yaml.Marshal(&allSettings)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"settings": allSettings,
			"err":      err,
		}).Panicln("Failed to marshall config to string")
	}
	return fmt.Sprintf("%s\n", y)
}

const (
	// Constants for viper variable names. Will be used to set
	// default values as well as to get each value

	varPostgresHost                         = "postgres.host"
	varPostgresPort                         = "postgres.port"
	varPostgresUser                         = "postgres.user"
	varPostgresDatabase                     = "postgres.database"
	varPostgresPassword                     = "postgres.password"
	varPostgresSSLMode                      = "postgres.sslmode"
	varPostgresConnectionTimeout            = "postgres.connection.timeout"
	varPostgresTransactionTimeout           = "postgres.transaction.timeout"
	varPostgresConnectionRetrySleep         = "postgres.connection.retrysleep"
	varPostgresConnectionMaxIdle            = "postgres.connection.maxidle"
	varPostgresConnectionMaxOpen            = "postgres.connection.maxopen"
	varHTTPAddress                          = "http.address"
	varMetricsHTTPAddress                   = "metrics.http.address"
	varDeveloperModeEnabled                 = "developer.mode.enabled"
	varKeycloakSecret                       = "keycloak.secret"
	varKeycloakClientID                     = "keycloak.client.id"
	varPublicOauthClientID                  = "public.oauth.client.id"
	varKeycloakDomainPrefix                 = "keycloak.domain.prefix"
	varKeycloakRealm                        = "keycloak.realm"
	varKeycloakTesUserName                  = "keycloak.testuser.name"
	varKeycloakTesUserSecret                = "keycloak.testuser.secret"
	varKeycloakTesUser2Name                 = "keycloak.testuser2.name"
	varKeycloakTesUser2Secret               = "keycloak.testuser2.secret"
	varKeycloakURL                          = "keycloak.url"
	varKeycloakEndpointAdmin                = "keycloak.endpoint.admin"
	varKeycloakEndpointAuth                 = "keycloak.endpoint.auth"
	varKeycloakEndpointToken                = "keycloak.endpoint.token"
	varKeycloakEndpointUserinfo             = "keycloak.endpoint.userinfo"
	varKeycloakEndpointAuthzResourceset     = "keycloak.endpoint.authz.resourceset"
	varKeycloakEndpointClients              = "keycloak.endpoint.clients"
	varKeycloakEndpointEntitlement          = "keycloak.endpoint.entitlement"
	varKeycloakEndpointBroker               = "keycloak.endpoint.broker"
	varKeycloakEndpointAccount              = "keycloak.endpoint.account"
	varKeycloakEndpointLogout               = "keycloak.endpoint.logout"
	varServiceAccountPrivateKeyDeprecated   = "serviceaccount.privatekey.deprecated"
	varServiceAccountPrivateKeyIDDeprecated = "serviceaccount.privatekeyid.deprecated"
	varServiceAccountPrivateKey             = "serviceaccount.privatekey"
	varServiceAccountPrivateKeyID           = "serviceaccount.privatekeyid"
	varGitHubClientID                       = "github.client.id"
	varGitHubClientSecret                   = "github.client.secret"
	varGitHubClientDefaultScopes            = "github.client.defaultscopes"
	varOSOClientApiUrl                      = "oso.client.apiurl"
	varTLSInsecureSkipVerify                = "tls.insecureskipverify"
	varNotApprovedRedirect                  = "notapproved.redirect"
	varHeaderMaxLength                      = "header.maxlength"
	varCacheControlUsers                    = "cachecontrol.users"
	varCacheControlCollaborators            = "cachecontrol.collaborators"
	varCacheControlUser                     = "cachecontrol.user"
	varUsersListLimit                       = "users.listlimit"
	defaultConfigFile                       = "config.yaml"
	varValidRedirectURLs                    = "redirect.valid"
	varLogLevel                             = "log.level"
	varLogJSON                              = "log.json"
	varWITDomainPrefix                      = "wit.domain.prefix"
	varWITURL                               = "wit.url"
	varNotificationServiceURL               = "notification.serviceurl"

	varTenantServiceURL = "tenant.serviceurl"

	varKeycloakTestsDisabled = "keycloak.tests.disabled"
)

type serviceAccountConfig struct {
	Accounts []ServiceAccount
}

type osoClusterConfig struct {
	Clusters []OSOCluster
}

// ServiceAccount represents a service account configuration
type ServiceAccount struct {
	Name    string   `mapstructure:"name"`
	ID      string   `mapstructure:"id"`
	Secrets []string `mapstructure:"secrets"`
}

// OSOCluster represents an OSO cluster configuration
type OSOCluster struct {
	Name                   string `mapstructure:"name"`
	URL                    string `mapstructure:"url"`
	ServiceAccountToken    string `mapstructure:"service-account-token"`
	TokenProviderID        string `mapstructure:"token-provider-id"`
	AuthClientID           string `mapstructure:"auth-client-id"`
	AuthClientSecret       string `mapstructure:"auth-client-secret"`
	AuthClientDefaultScope string `mapstructure:"auth-client-default-scope"`
}

// ConfigurationData encapsulates the Viper configuration object which stores the configuration data in-memory.
type ConfigurationData struct {
	// Main Configuration
	v *viper.Viper

	// Service Account Configuration is a map of service accounts where the key == the service account ID
	sa map[string]ServiceAccount

	// OSO Cluster Configuration is a map of clusters where the key == the OSO cluster API URL
	clusters map[string]OSOCluster

	defaultConfigurationError error
}

// NewConfigurationData creates a configuration reader object using configurable configuration file paths
func NewConfigurationData(mainConfigFile string, serviceAccountConfigFile string, osoClusterConfigFile string) (*ConfigurationData, error) {
	c := ConfigurationData{
		v: viper.New(),
	}

	// Set up the main configuration
	c.v.SetEnvPrefix("AUTH")
	c.v.AutomaticEnv()
	c.v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	c.v.SetTypeByDefaultValue(true)
	c.setConfigDefaults()

	if mainConfigFile != "" {
		c.v.SetConfigType("yaml")
		c.v.SetConfigFile(mainConfigFile)
		err := c.v.ReadInConfig() // Find and read the config file
		if err != nil {           // Handle errors reading the config file
			return nil, errors.Errorf("Fatal error config file: %s \n", err)
		}
	}

	// Set up the service account configuration (stored in a separate config file)
	saViper, defaultConfigErrorMsg, err := readFromJSONFile(serviceAccountConfigFile, defaultServiceAccountConfigPath, serviceAccountConfigFileName)
	c.appendDefaultConfigErrorMessage(defaultConfigErrorMsg)

	var saConf serviceAccountConfig
	err = saViper.UnmarshalExact(&saConf)
	if err != nil {
		return nil, err
	}
	c.sa = map[string]ServiceAccount{}
	for _, account := range saConf.Accounts {
		c.sa[account.ID] = account
	}

	// Set up the OSO cluster configuration (stored in a separate config file)
	clusterViper, defaultConfigErrorMsg, err := readFromJSONFile(osoClusterConfigFile, defaultOsoClusterConfigPath, osoClusterConfigFileName)
	c.appendDefaultConfigErrorMessage(defaultConfigErrorMsg)

	var clusterConf osoClusterConfig
	err = clusterViper.UnmarshalExact(&clusterConf)
	if err != nil {
		return nil, err
	}
	c.clusters = map[string]OSOCluster{}
	for _, cluster := range clusterConf.Clusters {
		c.clusters[cluster.URL] = cluster
	}

	// Check sensitive default configuration
	if c.IsPostgresDeveloperModeEnabled() {
		msg := "developer Mode is enabled"
		c.appendDefaultConfigErrorMessage(&msg)
	}
	key, kid := c.GetServiceAccountPrivateKey()
	if string(key) == DefaultServiceAccountPrivateKey {
		msg := "default service account private key is used"
		c.appendDefaultConfigErrorMessage(&msg)
	}
	if kid == defaultServiceAccountPrivateKeyID {
		msg := "default service account private key ID is used"
		c.appendDefaultConfigErrorMessage(&msg)
	}
	if c.GetPostgresPassword() == defaultDBPassword {
		msg := "default DB password is used"
		c.appendDefaultConfigErrorMessage(&msg)
	}
	if c.GetKeycloakSecret() == defaultKeycloakSecret {
		msg := "default Keycloak client secret is used"
		c.appendDefaultConfigErrorMessage(&msg)
	}
	if c.GetGitHubClientSecret() == defaultGitHubClientSecret {
		msg := "default GitHub client secret is used"
		c.appendDefaultConfigErrorMessage(&msg)
	}
	if c.IsTLSInsecureSkipVerify() {
		msg := "TLS verification disabled"
		c.appendDefaultConfigErrorMessage(&msg)
	}
	if c.GetValidRedirectURLs() == ".*" {
		msg := "no restrictions for valid redirect URLs"
		c.appendDefaultConfigErrorMessage(&msg)
	}
	if c.defaultConfigurationError != nil {
		log.WithFields(map[string]interface{}{
			"default_configuration_error": c.defaultConfigurationError.Error(),
		}).Warningln("Default config is used! This is OK in Dev Mode.")
	}

	return &c, nil
}

func readFromJSONFile(configFilePath string, defaultConfigFilePath string, configFileName string) (*viper.Viper, *string, error) {
	jsonViper := viper.New()
	jsonViper.SetTypeByDefaultValue(true)

	var err error
	var etcJSONConfigUsed bool
	var defaultConfigErrorMsg *string
	if configFilePath != "" {
		// If a JSON configuration file has been specified, check if it exists
		if _, err := os.Stat(configFilePath); err != nil {
			return nil, nil, err
		}
	} else {
		// If the JSON configuration file has not been specified
		// then we default to <defaultConfigFile>
		configFilePath, err = pathExists(defaultConfigFilePath)
		if err != nil {
			return nil, nil, err
		}
		etcJSONConfigUsed = configFilePath != ""
	}

	if !etcJSONConfigUsed {
		errMsg := fmt.Sprintf("%s is not used", defaultConfigFilePath)
		defaultConfigErrorMsg = &errMsg
	}

	jsonViper.SetConfigType("json")
	if configFilePath == "" {
		// Load the default config
		data, err := Asset(configFileName)
		if err != nil {
			return nil, nil, err
		}
		jsonViper.ReadConfig(bytes.NewBuffer(data))
	} else {
		jsonViper.SetConfigFile(configFilePath)
		err := jsonViper.ReadInConfig()
		if err != nil {
			return nil, nil, errors.Errorf("failed to load the JSON config file (%s): %s \n", configFilePath, err)
		}
	}

	return jsonViper, defaultConfigErrorMsg, nil
}

func (c *ConfigurationData) appendDefaultConfigErrorMessage(message *string) {
	if message == nil {
		return
	}
	if c.defaultConfigurationError == nil {
		c.defaultConfigurationError = errors.New(*message)
	} else {
		c.defaultConfigurationError = errors.Errorf("%s; %s", c.defaultConfigurationError.Error(), *message)
	}
}

func pathExists(pathToCheck string) (string, error) {
	_, err := os.Stat(pathToCheck)
	if err == nil {
		return pathToCheck, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return "", nil
}

func getMainConfigFile() string {
	// This was either passed as a env var or set inside main.go from --config
	envConfigPath, _ := os.LookupEnv("AUTH_CONFIG_FILE_PATH")
	return envConfigPath
}

func getServiceAccountConfigFile() string {
	envServiceAccountConfigFile, _ := os.LookupEnv("AUTH_SERVICE_ACCOUNT_CONFIG_FILE")
	return envServiceAccountConfigFile
}

func getOSOClusterConfigFile() string {
	envOSOClusterConfigFile, _ := os.LookupEnv("AUTH_OSO_CLUSTER_CONFIG_FILE")
	return envOSOClusterConfigFile
}

// DefaultConfigurationError returns an error if the default values is used
// for sensitive configuration like service account secrets or private keys.
// Error contains all the details.
// Returns nil if the default configuration is not used.
func (c *ConfigurationData) DefaultConfigurationError() error {
	return c.defaultConfigurationError
}

// GetServiceAccounts returns a map of service account configurations by service account ID
func (c *ConfigurationData) GetServiceAccounts() map[string]ServiceAccount {
	return c.sa
}

// GetOSOClusters returns a map of OSO cluster configurations by cluster API URL
func (c *ConfigurationData) GetOSOClusters() map[string]OSOCluster {
	return c.clusters
}

// GetDefaultConfigurationFile returns the default configuration file.
func (c *ConfigurationData) GetDefaultConfigurationFile() string {
	return defaultConfigFile
}

// GetConfigurationData is a wrapper over NewConfigurationData which reads configuration file path
// from the environment variable.
func GetConfigurationData() (*ConfigurationData, error) {
	return NewConfigurationData(getMainConfigFile(), getServiceAccountConfigFile(), getOSOClusterConfigFile())
}

func (c *ConfigurationData) setConfigDefaults() {
	//---------
	// Postgres
	//---------

	// We already call this in NewConfigurationData() - do we need it again??
	c.v.SetTypeByDefaultValue(true)

	c.v.SetDefault(varPostgresHost, "localhost")
	c.v.SetDefault(varPostgresPort, 5433)
	c.v.SetDefault(varPostgresUser, "postgres")
	c.v.SetDefault(varPostgresDatabase, "postgres")
	c.v.SetDefault(varPostgresPassword, defaultDBPassword)
	c.v.SetDefault(varPostgresSSLMode, "disable")
	c.v.SetDefault(varPostgresConnectionTimeout, 5)
	c.v.SetDefault(varPostgresConnectionMaxIdle, -1)
	c.v.SetDefault(varPostgresConnectionMaxOpen, -1)

	// Number of seconds to wait before trying to connect again
	c.v.SetDefault(varPostgresConnectionRetrySleep, time.Duration(time.Second))

	// Timeout of a transaction in minutes
	c.v.SetDefault(varPostgresTransactionTimeout, time.Duration(5*time.Minute))

	//-----
	// HTTP
	//-----
	c.v.SetDefault(varHTTPAddress, "0.0.0.0:8089")
	c.v.SetDefault(varMetricsHTTPAddress, "0.0.0.0:8089")
	c.v.SetDefault(varHeaderMaxLength, defaultHeaderMaxLength)

	//-----
	// Misc
	//-----

	// Enable development related features, e.g. token generation endpoint
	c.v.SetDefault(varDeveloperModeEnabled, false)

	c.v.SetDefault(varLogLevel, defaultLogLevel)

	// WIT related defaults
	c.v.SetDefault(varWITDomainPrefix, defaultWITDomainPrefix)

	// Auth-related defaults
	c.v.SetDefault(varKeycloakURL, devModeKeycloakURL)
	c.v.SetDefault(varServiceAccountPrivateKey, DefaultServiceAccountPrivateKey)
	c.v.SetDefault(varServiceAccountPrivateKeyID, defaultServiceAccountPrivateKeyID)
	c.v.SetDefault(varKeycloakClientID, defaultKeycloakClientID)
	c.v.SetDefault(varKeycloakSecret, defaultKeycloakSecret)
	c.v.SetDefault(varPublicOauthClientID, defaultPublicOauthClientID)
	c.v.SetDefault(varKeycloakDomainPrefix, defaultKeycloakDomainPrefix)
	c.v.SetDefault(varKeycloakTesUserName, defaultKeycloakTesUserName)
	c.v.SetDefault(varKeycloakTesUserSecret, defaultKeycloakTesUserSecret)
	c.v.SetDefault(varGitHubClientID, "c6a3a6280e9650ba27d8")
	c.v.SetDefault(varGitHubClientSecret, defaultGitHubClientSecret)
	c.v.SetDefault(varGitHubClientDefaultScopes, "admin:repo_hook read:org repo user gist")
	c.v.SetDefault(varOSOClientApiUrl, "https://api.starter-us-east-2.openshift.com")
	c.v.SetDefault(varTLSInsecureSkipVerify, false) // Do not set to true in production! True can be used only for testing.

	// Max number of users returned when searching users
	c.v.SetDefault(varUsersListLimit, 50)

	// HTTP Cache-Control/max-age default
	c.v.SetDefault(varCacheControlUsers, "max-age=2")
	c.v.SetDefault(varCacheControlCollaborators, "max-age=2")
	// data returned from '/api/user' must not be cached by intermediate proxies,
	// but can only be kept in the client's local cache.
	c.v.SetDefault(varCacheControlUser, "private,max-age=10")

	c.v.SetDefault(varKeycloakTesUser2Name, defaultKeycloakTesUser2Name)
	c.v.SetDefault(varKeycloakTesUser2Secret, defaultKeycloakTesUser2Secret)

	// Keycloak Tests are disabled by default
	c.v.SetDefault(varKeycloakTestsDisabled, true)
}

// GetPostgresHost returns the postgres host as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresHost() string {
	return c.v.GetString(varPostgresHost)
}

// GetPostgresPort returns the postgres port as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresPort() int64 {
	return c.v.GetInt64(varPostgresPort)
}

// GetPostgresUser returns the postgres user as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresUser() string {
	return c.v.GetString(varPostgresUser)
}

// GetPostgresDatabase returns the postgres database as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresDatabase() string {
	return c.v.GetString(varPostgresDatabase)
}

// GetPostgresPassword returns the postgres password as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresPassword() string {
	return c.v.GetString(varPostgresPassword)
}

// GetPostgresSSLMode returns the postgres sslmode as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresSSLMode() string {
	return c.v.GetString(varPostgresSSLMode)
}

// GetPostgresConnectionTimeout returns the postgres connection timeout as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresConnectionTimeout() int64 {
	return c.v.GetInt64(varPostgresConnectionTimeout)
}

// GetPostgresConnectionRetrySleep returns the number of seconds (as set via default, config file, or environment variable)
// to wait before trying to connect again
func (c *ConfigurationData) GetPostgresConnectionRetrySleep() time.Duration {
	return c.v.GetDuration(varPostgresConnectionRetrySleep)
}

// GetPostgresTransactionTimeout returns the number of minutes to timeout a transaction
func (c *ConfigurationData) GetPostgresTransactionTimeout() time.Duration {
	return c.v.GetDuration(varPostgresTransactionTimeout)
}

// GetPostgresConnectionMaxIdle returns the number of connections that should be keept alive in the database connection pool at
// any given time. -1 represents no restrictions/default behavior
func (c *ConfigurationData) GetPostgresConnectionMaxIdle() int {
	return c.v.GetInt(varPostgresConnectionMaxIdle)
}

// GetPostgresConnectionMaxOpen returns the max number of open connections that should be open in the database connection pool.
// -1 represents no restrictions/default behavior
func (c *ConfigurationData) GetPostgresConnectionMaxOpen() int {
	return c.v.GetInt(varPostgresConnectionMaxOpen)
}

// GetPostgresConfigString returns a ready to use string for usage in sql.Open()
func (c *ConfigurationData) GetPostgresConfigString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		c.GetPostgresHost(),
		c.GetPostgresPort(),
		c.GetPostgresUser(),
		c.GetPostgresPassword(),
		c.GetPostgresDatabase(),
		c.GetPostgresSSLMode(),
		c.GetPostgresConnectionTimeout(),
	)
}

// GetHTTPAddress returns the HTTP address (as set via default, config file, or environment variable)
// that the auth server binds to (e.g. "0.0.0.0:8089")
func (c *ConfigurationData) GetHTTPAddress() string {
	return c.v.GetString(varHTTPAddress)
}

// GetMetricsHTTPAddress returns the address the /metrics endpoing will be mounted.
// By default GetMetricsHTTPAddress is the same as GetHTTPAddress
func (c *ConfigurationData) GetMetricsHTTPAddress() string {
	return c.v.GetString(varMetricsHTTPAddress)
}

// GetHeaderMaxLength returns the max length of HTTP headers allowed in the system
// For example it can be used to limit the size of bearer tokens returned by the api service
func (c *ConfigurationData) GetHeaderMaxLength() int64 {
	return c.v.GetInt64(varHeaderMaxLength)
}

// IsPostgresDeveloperModeEnabled returns if development related features (as set via default, config file, or environment variable),
// e.g. token generation endpoint are enabled
func (c *ConfigurationData) IsPostgresDeveloperModeEnabled() bool {
	return c.v.GetBool(varDeveloperModeEnabled)
}

// GetMaxUsersListLimit returns the max number of users returned when searching users
func (c *ConfigurationData) GetMaxUsersListLimit() int {
	return c.v.GetInt(varUsersListLimit)
}

// GetCacheControlUsers returns the value to set in the "Cache-Control" HTTP response header
// when returning users.
func (c *ConfigurationData) GetCacheControlUsers() string {
	return c.v.GetString(varCacheControlUsers)
}

// GetCacheControlCollaborators returns the value to set in the "Cache-Control" HTTP response header
// when returning collaborators.
func (c *ConfigurationData) GetCacheControlCollaborators() string {
	return c.v.GetString(varCacheControlCollaborators)
}

// GetCacheControlUser returns the value to set in the "Cache-Control" HTTP response header
// when data for the current user.
func (c *ConfigurationData) GetCacheControlUser() string {
	return c.v.GetString(varCacheControlUser)
}

// GetDeprecatedServiceAccountPrivateKey returns the deprecated service account private key (if any) and its ID
// that is used to verify the service account authentication tokens during key rotation.
func (c *ConfigurationData) GetDeprecatedServiceAccountPrivateKey() ([]byte, string) {
	return []byte(c.v.GetString(varServiceAccountPrivateKeyDeprecated)), c.v.GetString(varServiceAccountPrivateKeyIDDeprecated)
}

// GetServiceAccountPrivateKey returns the service account private key and its ID
// that is used to sign the service account authentication tokens.
func (c *ConfigurationData) GetServiceAccountPrivateKey() ([]byte, string) {
	return []byte(c.v.GetString(varServiceAccountPrivateKey)), c.v.GetString(varServiceAccountPrivateKeyID)
}

// GetGitHubClientID return GitHub client ID used to link GitHub accounts
func (c *ConfigurationData) GetGitHubClientID() string {
	return c.v.GetString(varGitHubClientID)
}

// GetGitHubClientSecret return GitHub client secret used to link GitHub accounts
func (c *ConfigurationData) GetGitHubClientSecret() string {
	return c.v.GetString(varGitHubClientSecret)
}

// GetGitHubClientDefaultScopes return default scopes used to link GitHub accounts
func (c *ConfigurationData) GetGitHubClientDefaultScopes() string {
	return c.v.GetString(varGitHubClientDefaultScopes)
}

// GetOpenShiftClientApiUrl return the default OpenShift cluster client API URL used to link OpenShift accounts
func (c *ConfigurationData) GetOpenShiftClientApiUrl() string {
	return c.v.GetString(varOSOClientApiUrl)
}

// IsTLSInsecureSkipVerify returns true the client should not verify the
// server's certificate chain and host name. This mode should be used only for testing.
func (c *ConfigurationData) IsTLSInsecureSkipVerify() bool {
	return c.v.GetBool(varTLSInsecureSkipVerify)
}

// GetNotApprovedRedirect returns the URL to redirect to if the user is not approved
// May return empty string which means an unauthorized error should be returned instead of redirecting the user
func (c *ConfigurationData) GetNotApprovedRedirect() string {
	return c.v.GetString(varNotApprovedRedirect)
}

// GetKeycloakSecret returns the keycloak client secret (as set via config file or environment variable)
// that is used to make authorized Keycloak API Calls.
func (c *ConfigurationData) GetKeycloakSecret() string {
	return c.v.GetString(varKeycloakSecret)
}

// GetKeycloakClientID returns the keycloak client ID (as set via config file or environment variable)
// that is used to make authorized Keycloak API Calls.
func (c *ConfigurationData) GetKeycloakClientID() string {
	return c.v.GetString(varKeycloakClientID)
}

// GetPublicOauthClientID returns the public clientID
func (c *ConfigurationData) GetPublicOauthClientID() string {
	return c.v.GetString(varPublicOauthClientID)
}

// GetKeycloakDomainPrefix returns the domain prefix which should be used in all Keycloak requests
func (c *ConfigurationData) GetKeycloakDomainPrefix() string {
	return c.v.GetString(varKeycloakDomainPrefix)
}

// GetKeycloakRealm returns the keycloak realm name
func (c *ConfigurationData) GetKeycloakRealm() string {
	if c.v.IsSet(varKeycloakRealm) {
		return c.v.GetString(varKeycloakRealm)
	}
	if c.IsPostgresDeveloperModeEnabled() {
		return devModeKeycloakRealm
	}
	return defaultKeycloakRealm
}

func (c *ConfigurationData) IsKeycloakTestsDisabled() bool {
	return c.v.GetBool(varKeycloakTestsDisabled)
}

// GetKeycloakTestUserName returns the keycloak test user name used to obtain a test token (as set via config file or environment variable)
func (c *ConfigurationData) GetKeycloakTestUserName() string {
	return c.v.GetString(varKeycloakTesUserName)
}

// GetKeycloakTestUserSecret returns the keycloak test user password used to obtain a test token (as set via config file or environment variable)
func (c *ConfigurationData) GetKeycloakTestUserSecret() string {
	return c.v.GetString(varKeycloakTesUserSecret)
}

// GetKeycloakTestUser2Name returns the keycloak test user name used to obtain a test token (as set via config file or environment variable)
func (c *ConfigurationData) GetKeycloakTestUser2Name() string {
	return c.v.GetString(varKeycloakTesUser2Name)
}

// GetKeycloakTestUser2Secret returns the keycloak test user password used to obtain a test token (as set via config file or environment variable)
func (c *ConfigurationData) GetKeycloakTestUser2Secret() string {
	return c.v.GetString(varKeycloakTesUser2Secret)
}

func (c *ConfigurationData) GetKeycloakEndpointCerts() string {
	return fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/certs", c.v.GetString(varKeycloakURL), c.GetKeycloakRealm())
}

// GetKeycloakEndpointAuth returns the keycloak auth endpoint set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAuth(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointAuth, "auth")
}

// GetKeycloakEndpointToken returns the keycloak token endpoint set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointToken(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointToken, "token")
}

// GetKeycloakEndpointUserInfo returns the keycloak userinfo endpoint set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointUserInfo(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointUserinfo, "userinfo")
}

// GetNotificationServiceURL returns the URL for the Notification service used for event notification
func (c *ConfigurationData) GetNotificationServiceURL() string {
	return c.v.GetString(varNotificationServiceURL)
}

// GetKeycloakEndpointAdmin returns the <keycloak>/realms/admin/<realm> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAdmin(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAdmin, "auth/admin/realms/"+c.GetKeycloakRealm())
}

// GetKeycloakEndpointUsers returns the <keycloak>/realms/admin/<realm>/users endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointUsers(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAdmin, "auth/admin/realms/"+c.GetKeycloakRealm()+"/users")

}

// GetKeycloakEndpointIDP returns the <keycloak>/realms/admin/<realm>/users/USER_ID/federated-identity/rhd endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointLinkIDP(req *goa.RequestData, id string, idp string) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAdmin, "auth/admin/realms/"+c.GetKeycloakRealm()+"/users/"+id+"/federated-identity/"+idp)
}

// GetKeycloakEndpointAuthzResourceset returns the <keycloak>/realms/<realm>/authz/protection/resource_set endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAuthzResourceset(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAuthzResourceset, "auth/realms/"+c.GetKeycloakRealm()+"/authz/protection/resource_set")
}

// GetKeycloakEndpointClients returns the <keycloak>/admin/realms/<realm>/clients endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointClients(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointClients, "auth/admin/realms/"+c.GetKeycloakRealm()+"/clients")
}

// GetKeycloakEndpointEntitlement returns the <keycloak>/realms/<realm>/authz/entitlement/<clientID> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointEntitlement(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointEntitlement, "auth/realms/"+c.GetKeycloakRealm()+"/authz/entitlement/"+c.GetKeycloakClientID())
}

// GetKeycloakEndpointBroker returns the <keycloak>/realms/<realm>/authz/entitlement/<clientID> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointBroker(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointBroker, "auth/realms/"+c.GetKeycloakRealm()+"/broker")
}

// GetKeycloakAccountEndpoint returns the API URL for Read and Update on Keycloak User Accounts.
func (c *ConfigurationData) GetKeycloakAccountEndpoint(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAccount, "auth/realms/"+c.GetKeycloakRealm()+"/account")
}

// GetKeycloakEndpointLogout returns the keycloak logout endpoint set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointLogout(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointLogout, "logout")
}

// GetKeycloakDevModeURL returns Keycloak URL used by default in Dev mode
func (c *ConfigurationData) GetKeycloakDevModeURL() string {
	return devModeKeycloakURL
}

// GetKeycloakURL returns Keycloak URL used by default
func (c *ConfigurationData) GetKeycloakURL() string {
	return c.v.GetString(varKeycloakURL)
}

// GetWITDomainPrefix returns the domain prefix which should be used in requests to the auth service
func (c *ConfigurationData) GetWITDomainPrefix() string {
	return c.v.GetString(varWITDomainPrefix)
}

// GetWITURL returns the WIT URL where WIT is running
// If AUTH_WIT_URL is not set and Auth in not in Dev Mode then we calculate the URL from the domain
func (c *ConfigurationData) GetWITURL(req *goa.RequestData) (string, error) {
	if c.v.IsSet(varWITURL) {
		return c.v.GetString(varWITURL), nil
	}
	if c.IsPostgresDeveloperModeEnabled() {
		return devModeWITURL, nil
	}
	return c.calculateWITURL(req)
}

// GetTenantServiceURL returns the URL for the Tenant service used by login to initialize OSO tenant space
func (c *ConfigurationData) GetTenantServiceURL() string {
	return c.v.GetString(varTenantServiceURL)
}

func (c *ConfigurationData) getKeycloakOpenIDConnectEndpoint(req *goa.RequestData, endpointVarName string, pathSufix string) (string, error) {
	return c.getKeycloakEndpoint(req, endpointVarName, c.openIDConnectPath(pathSufix))
}

func (c *ConfigurationData) getKeycloakEndpoint(req *goa.RequestData, endpointVarName string, pathSufix string) (string, error) {
	if c.v.IsSet(endpointVarName) {
		return c.v.GetString(endpointVarName), nil
	}
	var endpoint string
	var err error
	if c.v.IsSet(varKeycloakURL) {
		// Keycloak URL is set. Calculate the URL endpoint
		endpoint = fmt.Sprintf("%s/%s", c.v.GetString(varKeycloakURL), pathSufix)
	} else {
		if c.IsPostgresDeveloperModeEnabled() {
			// Devmode is enabled. Calculate the URL endopoint using the devmode Keycloak URL
			endpoint = fmt.Sprintf("%s/%s", devModeKeycloakURL, pathSufix)
		} else {
			// Calculate relative URL based on request
			endpoint, err = c.getKeycloakURL(req, pathSufix)
			if err != nil {
				return "", err
			}
		}
	}

	// Can't set this variable because viper is not thread-safe. See https://github.com/spf13/viper/issues/268
	// c.v.Set(endpointVarName, endpoint) // Set the variable, so, we don't have to recalculate it again the next time
	return endpoint, nil
}

func (c *ConfigurationData) openIDConnectPath(suffix string) string {
	return "auth/realms/" + c.GetKeycloakRealm() + "/protocol/openid-connect/" + suffix
}

func (c *ConfigurationData) getKeycloakURL(req *goa.RequestData, path string) (string, error) {
	scheme := "http"
	if req.URL != nil && req.URL.Scheme == "https" { // isHTTPS
		scheme = "https"
	}
	xForwardProto := req.Header.Get("X-Forwarded-Proto")
	if xForwardProto != "" {
		scheme = xForwardProto
	}

	newHost, err := rest.ReplaceDomainPrefix(req.Host, c.GetKeycloakDomainPrefix())
	if err != nil {
		return "", err
	}
	newURL := fmt.Sprintf("%s://%s/%s", scheme, newHost, path)

	return newURL, nil
}

func (c *ConfigurationData) calculateWITURL(req *goa.RequestData) (string, error) {
	scheme := "http"
	if req.URL != nil && req.URL.Scheme == "https" { // isHTTPS
		scheme = "https"
	}
	xForwardProto := req.Header.Get("X-Forwarded-Proto")
	if xForwardProto != "" {
		scheme = xForwardProto
	}

	newHost, err := rest.ReplaceDomainPrefix(req.Host, c.GetWITDomainPrefix())
	if err != nil {
		return "", err
	}
	newURL := fmt.Sprintf("%s://%s", scheme, newHost)

	return newURL, nil
}

// GetLogLevel returns the logging level (as set via config file or environment variable)
func (c *ConfigurationData) GetLogLevel() string {
	return c.v.GetString(varLogLevel)
}

// IsLogJSON returns if we should log json format (as set via config file or environment variable)
func (c *ConfigurationData) IsLogJSON() bool {
	if c.v.IsSet(varLogJSON) {
		return c.v.GetBool(varLogJSON)
	}
	if c.IsPostgresDeveloperModeEnabled() {
		return false
	}
	return true
}

// GetValidRedirectURLs returns the RegEx of valid redirect URLs for auth requests
// If AUTH_REDIRECT_VALID is not set then in Dev Mode all redirects allowed - *
// Otherwise only *.openshift.io URLs are considered valid
func (c *ConfigurationData) GetValidRedirectURLs() string {
	if c.v.IsSet(varValidRedirectURLs) {
		return c.v.GetString(varValidRedirectURLs)
	}
	if c.IsPostgresDeveloperModeEnabled() {
		return devModeValidRedirectURLs
	}
	return DefaultValidRedirectURLs
}

const (
	defaultHeaderMaxLength = 5000 // bytes

	// Auth-related defaults

	// RSAPrivateKey for signing JWT Tokens for service accounts
	// ssh-keygen -f alm_rsa
	DefaultServiceAccountPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAnwrjH5iTSErw9xUptp6QSFoUfpHUXZ+PaslYSUrpLjw1q27O
DSFwmhV4+dAaTMO5chFv/kM36H3ZOyA146nwxBobS723okFaIkshRrf6qgtD6coT
HlVUSBTAcwKEjNn4C9jtEpyOl+eSgxhMzRH3bwTIFlLlVMiZf7XVE7P3yuOCpqkk
2rdYVSpQWQWKU+ZRywJkYcLwjEYjc70AoNpjO5QnY+Exx98E30iEdPHZpsfNhsjh
9Z7IX5TrMYgz7zBTw8+niO/uq3RBaHyIhDbvenbR9Q59d88lbnEeHKgSMe2RQpFR
3rxFRkc/64Rn/bMuL/ptNowPqh1P+9GjYzWmPwIDAQABAoIBAQCBCl5ZpnvprhRx
BVTA/Upnyd7TCxNZmzrME+10Gjmz79pD7DV25ejsu/taBYUxP6TZbliF3pggJOv6
UxomTB4znlMDUz0JgyjUpkyril7xVQ6XRAPbGrS1f1Def+54MepWAn3oGeqASb3Q
bAj0Yl12UFTf+AZmkhQpUKk/wUeN718EIY4GRHHQ6ykMSqCKvdnVbMyb9sIzbSTl
v+l1nQFnB/neyJq6P0Q7cxlhVj03IhYj/AxveNlKqZd2Ih3m/CJo0Abtwhx+qHZp
cCBrYj7VelEaGARTmfoIVoGxFGKZNCcNzn7R2ic7safxXqeEnxugsAYX/UmMoq1b
vMYLcaLRAoGBAMqMbbgejbD8Cy6wa5yg7XquqOP5gPdIYYS88TkQTp+razDqKPIU
hPKetnTDJ7PZleOLE6eJ+dQJ8gl6D/dtOsl4lVRy/BU74dk0fYMiEfiJMYEYuAU0
MCramo3HAeySTP8pxSLFYqJVhcTpL9+NQgbpJBUlx5bLDlJPl7auY077AoGBAMkD
UpJRIv/0gYSz5btVheEyDzcqzOMZUVsngabH7aoQ49VjKrfLzJ9WznzJS5gZF58P
vB7RLuIA8m8Y4FUwxOr4w9WOevzlFh0gyzgNY4gCwrzEryOZqYYqCN+8QLWfq/hL
+gYFYpEW5pJ/lAy2i8kPanC3DyoqiZCsUmlg6JKNAoGBAIdCkf6zgKGhHwKV07cs
DIqx2p0rQEFid6UB3ADkb+zWt2VZ6fAHXeT7shJ1RK0o75ydgomObWR5I8XKWqE7
s1dZjDdx9f9kFuVK1Upd1SxoycNRM4peGJB1nWJydEl8RajcRwZ6U+zeOc+OfWbH
WUFuLadlrEx5212CQ2k+OZlDAoGAdsH2w6kZ83xCFOOv41ioqx5HLQGlYLpxfVg+
2gkeWa523HglIcdPEghYIBNRDQAuG3RRYSeW+kEy+f4Jc2tHu8bS9FWkRcsWoIji
ZzBJ0G5JHPtaub6sEC6/ZWe0F1nJYP2KLop57FxKRt0G2+fxeA0ahpMwa2oMMiQM
4GM3pHUCgYEAj2ZjjsF2MXYA6kuPUG1vyY9pvj1n4fyEEoV/zxY1k56UKboVOtYr
BA/cKaLPqUF+08Tz/9MPBw51UH4GYfppA/x0ktc8998984FeIpfIFX6I2U9yUnoQ
OCCAgsB8g8yTB4qntAYyfofEoDiseKrngQT5DSdxd51A/jw7B8WyBK8=
-----END RSA PRIVATE KEY-----`

	defaultServiceAccountPrivateKeyID = "9MLnViaRkhVj1GT9kpWUkwHIwUD-wZfUxR-3CpkE-Xs"

	defaultDBPassword = "mysecretpassword"

	defaultGitHubClientSecret = "48d1498c849616dfecf83cf74f22dfb361ee2511"

	defaultLogLevel = "info"

	defaultKeycloakClientID     = "fabric8-online-platform"
	defaultKeycloakSecret       = "7a3d5a00-7f80-40cf-8781-b5b6f2dfd1bd"
	defaultPublicOauthClientID  = "740650a2-9c44-4db5-b067-a3d1b2cd2d01"
	defaultKeycloakDomainPrefix = "sso"
	defaultKeycloakRealm        = "fabric8"
	defaultWITDomainPrefix      = "api"

	// Github does not allow committing actual OAuth tokens no matter how less privilege the token has
	camouflagedAccessToken = "751e16a8b39c0985066-AccessToken-4871777f2c13b32be8550"

	defaultKeycloakTesUserName    = "testuser"
	defaultKeycloakTesUserSecret  = "testuser"
	defaultKeycloakTesUser2Name   = "testuser2"
	defaultKeycloakTesUser2Secret = "testuser2"

	// Keycloak vars to be used in dev mode. Can be overridden by setting up keycloak.url & keycloak.realm
	devModeKeycloakURL   = "https://sso.prod-preview.openshift.io"
	devModeKeycloakRealm = "fabric8-test"
	devModeWITURL        = "http://localhost:8080"

	// DefaultValidRedirectURLs is a regex to be used to whitelist redirect URL for auth
	// If the AUTH_REDIRECT_VALID env var is not set then in Dev Mode all redirects allowed - *
	// In prod mode the following regex will be used by default:
	DefaultValidRedirectURLs = "^(https|http)://(([^/?#]+[.])?(?i:openshift[.]io)|localhost)((/|:).*)?$" // *.openshift.io/* and localhost
	devModeValidRedirectURLs = ".*"

	serviceAccountConfigFileName    = "service-account-secrets.conf"
	defaultServiceAccountConfigPath = "/etc/fabric8/" + serviceAccountConfigFileName

	osoClusterConfigFileName    = "oso-clusters.conf"
	defaultOsoClusterConfigPath = "/etc/fabric8/" + osoClusterConfigFileName
)

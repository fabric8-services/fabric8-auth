package configuration

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	yaml "gopkg.in/yaml.v2"
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

	//------------------------------------------------------------------------------------------------------------------
	//
	// General
	//
	//------------------------------------------------------------------------------------------------------------------

	varHTTPAddress                         = "http.address"
	varMetricsHTTPAddress                  = "metrics.http.address"
	varDeveloperModeEnabled                = "developer.mode.enabled"
	varCleanTestDataEnabled                = "clean.test.data"
	varCleanTestDataErrorReportingRequired = "error.reporting.required"
	varDBLogsEnabled                       = "enable.db.logs"
	varNotApprovedRedirect                 = "notapproved.redirect"
	varHeaderMaxLength                     = "header.maxlength"
	varUsersListLimit                      = "users.listlimit"
	defaultConfigFile                      = "config.yaml"
	varValidRedirectURLs                   = "redirect.valid"
	varLogLevel                            = "log.level"
	varLogJSON                             = "log.json"
	varEmailVerifiedRedirectURL            = "email.verify.url"
	varInvitationAcceptedRedirectURL       = "invitation.accepted.url"
	varInternalUsersEmailAddressSuffix     = "internal.users.email.address.domain"
	varIgnoreEmailInProd                   = "ignore.email.prod"
	varPodName                             = "pod.name"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Postgres
	//
	//------------------------------------------------------------------------------------------------------------------

	varPostgresHost                 = "postgres.host"
	varPostgresPort                 = "postgres.port"
	varPostgresUser                 = "postgres.user"
	varPostgresDatabase             = "postgres.database"
	varPostgresPassword             = "postgres.password"
	varPostgresSSLMode              = "postgres.sslmode"
	varPostgresConnectionTimeout    = "postgres.connection.timeout"
	varPostgresTransactionTimeout   = "postgres.transaction.timeout"
	varPostgresConnectionRetrySleep = "postgres.connection.retrysleep"
	varPostgresConnectionMaxIdle    = "postgres.connection.maxidle"
	varPostgresConnectionMaxOpen    = "postgres.connection.maxopen"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Authentication Provider
	//
	//------------------------------------------------------------------------------------------------------------------

	varOAuthProviderType             = "oauth.provider.type"
	varOAuthProviderClientID         = "oauth.provider.client.id"
	varOAuthProviderClientSecret     = "oauth.provider.client.secret"
	varOAuthProviderEndpointAuth     = "oauth.provider.endpoint.auth"
	varOAuthProviderEndpointUserInfo = "oauth.provider.endpoint.userinfo"
	varOAuthProviderEndpointToken    = "oauth.provider.endpoint.token"
	varOAuthProviderEndpointLogout   = "oauth.provider.endpoint.logout"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Service Account Keys
	//
	//------------------------------------------------------------------------------------------------------------------

	// Private keys for signing OSIO Serivice Account tokens
	varServiceAccountPrivateKeyDeprecated   = "serviceaccount.privatekey.deprecated"
	varServiceAccountPrivateKeyIDDeprecated = "serviceaccount.privatekeyid.deprecated"
	varServiceAccountPrivateKey             = "serviceaccount.privatekey"
	varServiceAccountPrivateKeyID           = "serviceaccount.privatekeyid"

	//------------------------------------------------------------------------------------------------------------------
	//
	// User Keys
	//
	//------------------------------------------------------------------------------------------------------------------

	// Private keys for signing OSIO Access and Refresh tokens
	varUserAccountPrivateKeyDeprecated   = "useraccount.privatekey.deprecated"
	varUserAccountPrivateKeyIDDeprecated = "useraccount.privatekeyid.deprecated"
	varUserAccountPrivateKey             = "useraccount.privatekey"
	varUserAccountPrivateKeyID           = "useraccount.privatekeyid"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Token configuration
	//
	//------------------------------------------------------------------------------------------------------------------

	varAccessTokenExpiresIn    = "useraccount.token.access.expiresin"    // In seconds
	varRefreshTokenExpiresIn   = "useraccount.token.refresh.expiresin"   // In seconds
	varTransientTokenExpiresIn = "useraccount.token.transient.expiresin" // In seconds

	//------------------------------------------------------------------------------------------------------------------
	//
	// GitHub Linking
	//
	//------------------------------------------------------------------------------------------------------------------

	varGitHubClientID            = "github.client.id"
	varGitHubClientSecret        = "github.client.secret"
	varGitHubClientDefaultScopes = "github.client.defaultscopes"

	//------------------------------------------------------------------------------------------------------------------
	//
	// OSO
	//
	//------------------------------------------------------------------------------------------------------------------

	varOSOClientApiUrl                 = "oso.client.apiurl" // Default OSO cluster API URL
	varOSORegistrationAppURL           = "oso.regapp.serviceurl"
	varOSORegistrationAppAdminUsername = "oso.regapp.admin.username"
	varOSORegistrationAppAdminToken    = "oso.regapp.admin.token"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Cache control
	//
	//------------------------------------------------------------------------------------------------------------------

	varCacheControlUsers         = "cachecontrol.users"
	varCacheControlCollaborators = "cachecontrol.collaborators"
	varCacheControlUser          = "cachecontrol.user"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Other service URLs
	//
	//------------------------------------------------------------------------------------------------------------------

	varWITDomainPrefix        = "wit.domain.prefix"
	varTenantServiceURL       = "tenant.serviceurl"
	varCheServiceURL          = "che.serviceurl"
	varWITURL                 = "wit.url"
	varNotificationServiceURL = "notification.serviceurl"
	varAuthURL                = "auth.url"
	varShortClusterServiceURL = "cluster.url.short"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Privilege Cache
	//
	//------------------------------------------------------------------------------------------------------------------

	varPrivilegeCacheExpirySeconds = "privilege.cache.expiry.seconds"
	varRPTTokenMaxPermissions      = "rpt.token.max.permissions"

	//------------------------------------------------------------------------------------------------------------------
	//
	// User deactivation
	//
	//------------------------------------------------------------------------------------------------------------------

	varUserDeactivationEnabled             = "user.deactivation.enabled"
	varUserDeactivationNotificationEnabled = "user.deactivation.notification.enabled"
	// varUserDeactivationWorkerIntervalSeconds is the interval between 2 cycles of the user deactivation worker in minutes
	varUserDeactivationWorkerIntervalSeconds = "user.deactivation.interval.seconds"
	// varUserDeactivationNotificationWorkerIntervalSeconds is the interval between 2 cycles of the user deactivation notification worker in minutes
	varUserDeactivationNotificationWorkerIntervalSeconds = "user.deactivation.notification.interval.seconds"
	// varUserDeactivationFetchLimit the maximum number of identities to warn before deactivation and deactivate
	varUserDeactivationFetchLimit = "user.deactivation.fetch.limit"
	// varUserDeactivationInactivityPeriodNotification the number of days of inactivity before notifying the user of account deactivation
	varUserDeactivationInactivityNotificationPeriodDays = "user.deactivation.inactivity.notification.period.days"
	// varUserDeactivationInactivityPeriodDays the number of days of inactivity before deactivating the user account
	varUserDeactivationInactivityPeriodDays = "user.deactivation.inactivity.period.days"
	// varPostDeactivationNotificationDelayMillis the delay (in milliseconds) between 2 account deactivation notifications sent to users
	varPostDeactivationNotificationDelayMillis = "user.deactivation.post.notification.delay.millis"
	// varUserDeactivationWorkerRescheduleDelayHours the number of hours to wait after a failed deactivation attempt to attempt deactivation again
	varUserDeactivationWorkerRescheduleDelayHours = "user.deactivation.reschedule.delay.hours"

	//------------------------------------------------------------------------------------------------------------------
	//
	// Other
	//
	//------------------------------------------------------------------------------------------------------------------

	// Public Client ID for logging into Auth service via OAuth2
	varPublicOAuthClientID = "public.oauth.client.id"

	// Cluster information refresh interval in nanoseconds
	varClusterRefreshInterval = "cluster.refresh.int"

	// sentry
	varEnvironment = "environment"
	varSentryDSN   = "sentry.dsn"

	// Token cleanup
	varExpiredTokenRetentionHours = "expired.token.retention.hours"

	secondsInOneDay = 24 * 60 * 60
)

type serviceAccountConfig struct {
	Accounts []ServiceAccount
}

// ServiceAccount represents a service account configuration
type ServiceAccount struct {
	Name    string   `mapstructure:"name"`
	ID      string   `mapstructure:"id"`
	Secrets []string `mapstructure:"secrets"`
}

// ConfigurationData encapsulates the Viper configuration object which stores the configuration data in-memory.
type ConfigurationData struct {
	// Main Configuration
	v *viper.Viper

	// Service Account Configuration is a map of service accounts where the key == the service account ID
	sa map[string]ServiceAccount

	defaultConfigurationError error

	mux sync.RWMutex
}

// NewConfigurationData creates a configuration reader object using configurable configuration file paths
func NewConfigurationData(mainConfigFile string, serviceAccountConfigFile string) (*ConfigurationData, error) {
	c := &ConfigurationData{
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
		log.Infof("loading config from '%s'", mainConfigFile)
		err := c.v.ReadInConfig() // Find and read the config file
		if err != nil {           // Handle errors reading the config file
			return nil, errors.Errorf("Fatal error config file: %s \n", err)
		}
	}

	// Set up the service account configuration (stored in a separate config file)
	saViper, defaultConfigErrorMsg, _, err := readFromJSONFile(serviceAccountConfigFile, defaultServiceAccountConfigPath, serviceAccountConfigFileName)
	if err != nil {
		return nil, err
	}
	if defaultConfigErrorMsg != nil {
		c.appendDefaultConfigErrorMessage(*defaultConfigErrorMsg)
	}

	var saConf serviceAccountConfig
	err = saViper.UnmarshalExact(&saConf)
	if err != nil {
		return nil, err
	}
	c.sa = map[string]ServiceAccount{}
	for _, account := range saConf.Accounts {
		c.sa[account.ID] = account
	}
	c.checkServiceAccountConfig()

	// Check sensitive default configuration
	if c.IsPostgresDeveloperModeEnabled() {
		c.appendDefaultConfigErrorMessage("developer Mode is enabled")
	}
	key, kid := c.GetServiceAccountPrivateKey()
	if string(key) == DefaultServiceAccountPrivateKey {
		c.appendDefaultConfigErrorMessage("default service account private key is used")
	}
	if kid == defaultServiceAccountPrivateKeyID {
		c.appendDefaultConfigErrorMessage("default service account private key ID is used")
	}
	key, kid = c.GetUserAccountPrivateKey()
	if string(key) == DefaultUserAccountPrivateKey {
		c.appendDefaultConfigErrorMessage("default user account private key is used")
	}
	if kid == defaultUserAccountPrivateKeyID {
		c.appendDefaultConfigErrorMessage("default user account private key ID is used")
	}
	if c.GetPostgresPassword() == defaultDBPassword {
		c.appendDefaultConfigErrorMessage("default DB password is used")
	}
	if c.GetOAuthProviderClientSecret() == defaultOAuthProviderClientSecret {
		c.appendDefaultConfigErrorMessage("default auth provider client secret is used")
	}
	if c.GetGitHubClientSecret() == defaultGitHubClientSecret {
		c.appendDefaultConfigErrorMessage("default GitHub client secret is used")
	}
	if c.GetValidRedirectURLs() == ".*" {
		c.appendDefaultConfigErrorMessage("no restrictions for valid redirect URLs")
	}
	c.validateURL(c.GetNotificationServiceURL(), "notification service")
	if c.GetAccessTokenExpiresIn() < 3*60 {
		c.appendDefaultConfigErrorMessage("too short lifespan of access tokens")
	}
	if c.GetRefreshTokenExpiresIn() < 3*60 {
		c.appendDefaultConfigErrorMessage("too short lifespan of refresh tokens")
	}
	c.validateURL(c.GetOSORegistrationAppURL(), "OSO Reg App")
	if c.GetOSORegistrationAppAdminUsername() == "" {
		c.appendDefaultConfigErrorMessage("OSO Reg App admin username is empty")
	}
	if c.GetOSORegistrationAppAdminToken() == "" {
		c.appendDefaultConfigErrorMessage("OSO Reg App admin token is empty")
	}
	c.validateURL(c.GetAuthServiceURL(), "Auth service")
	if c.GetAuthServiceURL() == "http://localhost" {
		c.appendDefaultConfigErrorMessage("environment is expected to be set to 'production' or 'prod-preview'")
	}
	if c.GetSentryDSN() == "" {
		c.appendDefaultConfigErrorMessage("Sentry DSN is empty")
	}
	c.validateURL(c.GetClusterServiceURL(), "Cluster service")
	if c.GetClusterCacheRefreshInterval() < 5*time.Second || c.GetClusterCacheRefreshInterval() > time.Hour {
		c.appendDefaultConfigErrorMessage("Cluster cache refresh interval is less than five seconds or more than one hour")
	}
	if c.defaultConfigurationError != nil {
		log.WithFields(map[string]interface{}{
			"default_configuration_error": c.defaultConfigurationError.Error(),
		}).Warningln("Default config is used! This is OK in Dev Mode.")
	}

	return c, nil
}

func (c *ConfigurationData) validateURL(serviceURL, serviceName string) {
	if serviceURL == "" {
		c.appendDefaultConfigErrorMessage(fmt.Sprintf("%s url is empty", serviceName))
	} else {
		_, err := url.Parse(serviceURL)
		if err != nil {
			c.appendDefaultConfigErrorMessage(fmt.Sprintf("invalid %s url: %s", serviceName, err.Error()))
		}
	}
}

func (c *ConfigurationData) checkServiceAccountConfig() {
	notFoundServiceAccountNames := map[string]bool{
		"fabric8-wit":           true,
		"fabric8-tenant":        true,
		"fabric8-jenkins-idler": true,
		"fabric8-jenkins-proxy": true,
		"fabric8-oso-proxy":     true,
		"online-registration":   true,
		"fabric8-notification":  true,
		"rh-che":                true,
		"fabric8-gemini-server": true,
		"toolchain-operator":    true,
	}
	for _, sa := range c.sa {
		if sa.Name == "" {
			c.appendDefaultConfigErrorMessage("service account name is empty in service account config")
		} else {
			delete(notFoundServiceAccountNames, sa.Name)
		}
		if sa.ID == "" {
			c.appendDefaultConfigErrorMessage(fmt.Sprintf("%s service account ID is empty in service account config", sa.Name))
		}
		if len(sa.Secrets) == 0 {
			c.appendDefaultConfigErrorMessage(fmt.Sprintf("%s service account secret array is empty in service account config", sa.Name))
		}
	}
	if len(notFoundServiceAccountNames) != 0 {
		c.appendDefaultConfigErrorMessage("some expected service accounts are missing in service account config")
	}
}

func readFromJSONFile(configFilePath string, defaultConfigFilePath string, configFileName string) (*viper.Viper, *string, string, error) {
	jsonViper := viper.New()
	jsonViper.SetTypeByDefaultValue(true)

	var err error
	var etcJSONConfigUsed bool
	var defaultConfigErrorMsg *string
	if configFilePath != "" {
		// If a JSON configuration file has been specified, check if it exists
		if _, err := os.Stat(configFilePath); err != nil {
			return nil, nil, configFilePath, err
		}
	} else {
		// If the JSON configuration file has not been specified
		// then we default to <defaultConfigFile>
		configFilePath, err = pathExists(defaultConfigFilePath)
		if err != nil {
			return nil, nil, defaultConfigFilePath, err
		}
		etcJSONConfigUsed = configFilePath != ""
	}

	if !etcJSONConfigUsed {
		errMsg := fmt.Sprintf("%s is not used", defaultConfigFilePath)
		defaultConfigErrorMsg = &errMsg
	}
	usedFile := configFilePath

	jsonViper.SetConfigType("json")
	if configFilePath == "" {
		// Load the built-in config file (used in dev mode)
		usedFile = "./configuration/conf-files/" + configFileName
		data, err := Asset(configFileName)
		if err != nil {
			return nil, nil, usedFile, err
		}
		jsonViper.ReadConfig(bytes.NewBuffer(data))
	} else {
		jsonViper.SetConfigFile(configFilePath)
		err := jsonViper.ReadInConfig()
		if err != nil {
			return nil, nil, usedFile, errors.Errorf("failed to load the JSON config file (%s): %s \n", configFilePath, err)
		}
	}

	return jsonViper, defaultConfigErrorMsg, usedFile, nil
}

func (c *ConfigurationData) appendDefaultConfigErrorMessage(message string) {
	if c.defaultConfigurationError == nil {
		c.defaultConfigurationError = errors.New(message)
	} else {
		c.defaultConfigurationError = errors.Errorf("%s; %s", c.defaultConfigurationError.Error(), message)
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

// DefaultConfigurationError returns an error if the default values is used
// for sensitive configuration like service account secrets or private keys.
// Error contains all the details.
// Returns nil if the default configuration is not used.
func (c *ConfigurationData) DefaultConfigurationError() error {
	// Lock for reading because config file watcher can update config errors
	c.mux.RLock()
	defer c.mux.RUnlock()

	return c.defaultConfigurationError
}

// GetAuthServiceUrl returns Auth Service URL
func (c *ConfigurationData) GetAuthServiceURL() string {
	if c.v.IsSet(varAuthURL) {
		return c.v.GetString(varAuthURL)
	}
	switch c.GetEnvironment() {
	case prodEnvironment:
		return "https://auth.openshift.io"
	case prodPreviewEnvironment:
		return "https://auth.prod-preview.openshift.io"
	default:
		return "http://localhost"
	}
}

// GetServiceAccounts returns a map of service account configurations by service account ID
// Default Service Account names and secrets used in Dev mode:
// "fabric8-wit" : "witsecret"
// "fabric8-tenant : ["tenantsecretOld", "tenantsecretNew"]
// "fabric8-jenkins-idler : "secret"
// "fabric8-jenkins-proxy : "secret"
// "fabric8-oso-proxy : "secret"
// "online-registration : "secret"
// "fabric8-notification : "secret"
// "rh-che : "secret"
// "fabric8-gemini-server" : "secret"
// "toolchain-operator" : "secret"
func (c *ConfigurationData) GetServiceAccounts() map[string]ServiceAccount {
	return c.sa
}

//GetClusterServiceURL returns the short cluster service url
// "http://cluster" is the default URL
func (c *ConfigurationData) GetClusterServiceURL() string {
	return c.v.GetString(varShortClusterServiceURL)
}

func (c *ConfigurationData) GetClusterCacheRefreshInterval() time.Duration {
	return c.v.GetDuration(varClusterRefreshInterval)
}

// GetDefaultConfigurationFile returns the default configuration file.
func (c *ConfigurationData) GetDefaultConfigurationFile() string {
	return defaultConfigFile
}

// GetConfigurationData is a wrapper over NewConfigurationData which reads configuration file path
// from the environment variable.
func GetConfigurationData() (*ConfigurationData, error) {
	return NewConfigurationData(getMainConfigFile(), getServiceAccountConfigFile())
}

func (c *ConfigurationData) setConfigDefaults() {

	//------------------------------------------------------------------------------------------------------------------
	//
	// Postgres
	//
	//------------------------------------------------------------------------------------------------------------------

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

	//------------------------------------------------------------------------------------------------------------------
	//
	// Authentication Provider Defaults
	//
	//------------------------------------------------------------------------------------------------------------------

	c.v.SetDefault(varOAuthProviderType, defaultOAuthProviderType)
	c.v.SetDefault(varOAuthProviderClientID, defaultOAuthProviderClientID)
	c.v.SetDefault(varOAuthProviderClientSecret, defaultOAuthProviderClientSecret)
	c.v.SetDefault(varOAuthProviderEndpointAuth, defaultOAuthProviderEndpointAuth)
	c.v.SetDefault(varOAuthProviderEndpointToken, defaultOAuthProviderEndpointToken)
	c.v.SetDefault(varOAuthProviderEndpointUserInfo, defaultOAuthProviderEndpointUserInfo)
	c.v.SetDefault(varOAuthProviderEndpointLogout, defaultOAuthProviderEndpointLogout)

	//------------------------------------------------------------------------------------------------------------------
	//
	// Http
	//
	//------------------------------------------------------------------------------------------------------------------

	c.v.SetDefault(varHTTPAddress, "0.0.0.0:8089")
	c.v.SetDefault(varMetricsHTTPAddress, "0.0.0.0:8089")
	c.v.SetDefault(varHeaderMaxLength, defaultHeaderMaxLength)

	//------------------------------------------------------------------------------------------------------------------
	//
	// Misc
	//
	//------------------------------------------------------------------------------------------------------------------

	// Enable development related features, e.g. token generation endpoint
	c.v.SetDefault(varDeveloperModeEnabled, false)

	// By default, test data should be cleaned from DB, unless explicitely said otherwise.
	c.v.SetDefault(varCleanTestDataEnabled, true)
	// By default, error should be reported while cleaning test data from DB.
	c.v.SetDefault(varCleanTestDataErrorReportingRequired, true)
	// By default, DB logs are not output in the console
	c.v.SetDefault(varDBLogsEnabled, false)

	c.v.SetDefault(varLogLevel, defaultLogLevel)

	// By default, test data should be cleaned from DB, unless explicitely said otherwise.
	c.v.SetDefault(varCleanTestDataEnabled, true)
	// By default, DB logs are not output in the console
	c.v.SetDefault(varDBLogsEnabled, false)

	// WIT related defaults
	c.v.SetDefault(varWITDomainPrefix, defaultWITDomainPrefix)

	// Auth-related defaults
	c.v.SetDefault(varServiceAccountPrivateKey, DefaultServiceAccountPrivateKey)
	c.v.SetDefault(varServiceAccountPrivateKeyID, defaultServiceAccountPrivateKeyID)
	c.v.SetDefault(varUserAccountPrivateKey, DefaultUserAccountPrivateKey)
	c.v.SetDefault(varUserAccountPrivateKeyID, defaultUserAccountPrivateKeyID)
	var in30Days int64
	in30Days = 30 * 24 * 60 * 60
	c.v.SetDefault(varAccessTokenExpiresIn, in30Days)
	c.v.SetDefault(varRefreshTokenExpiresIn, in30Days)
	c.v.SetDefault(varTransientTokenExpiresIn, 60) // 60 seconds
	c.v.SetDefault(varPublicOAuthClientID, defaultPublicOAuthClientID)
	c.v.SetDefault(varGitHubClientID, "c6a3a6280e9650ba27d8")
	c.v.SetDefault(varGitHubClientSecret, defaultGitHubClientSecret)
	c.v.SetDefault(varGitHubClientDefaultScopes, "admin:repo_hook read:org public_repo read:user")
	c.v.SetDefault(varOSOClientApiUrl, "https://api.starter-us-east-2.openshift.com")
	c.v.SetDefault(varOSORegistrationAppURL, defaultOSORegistrationAppURL)
	c.v.SetDefault(varNotificationServiceURL, "http://notification.serviceurl")
	c.v.SetDefault(varOSORegistrationAppAdminUsername, "oso.regapp.admin.username")
	c.v.SetDefault(varOSORegistrationAppAdminToken, "oso.regapp.admin.token")
	// Max number of users returned when searching users
	c.v.SetDefault(varUsersListLimit, 50)

	// HTTP Cache-Control/max-age default
	c.v.SetDefault(varCacheControlUsers, "max-age=2")
	c.v.SetDefault(varCacheControlCollaborators, "max-age=2")
	// data returned from '/api/user' must not be cached by intermediate proxies,
	// but can only be kept in the client's local cache.
	c.v.SetDefault(varCacheControlUser, "private,max-age=10")

	// On email successful/failed verification, redirect to this page.
	c.v.SetDefault(varEmailVerifiedRedirectURL, "https://prod-preview.openshift.io/_home")

	// default email address suffix
	c.v.SetDefault(varInternalUsersEmailAddressSuffix, "@redhat.com")

	// Regex to be used to check if the user with such email should be ignored during account provisioning
	c.v.SetDefault(varIgnoreEmailInProd, ".+\\+preview.*\\@redhat\\.com")

	// prod-preview or prod
	c.v.SetDefault(varEnvironment, "local")

	// Privilege cache expiry
	c.v.SetDefault(varPrivilegeCacheExpirySeconds, secondsInOneDay)

	// RPT Token maximum permissions
	c.v.SetDefault(varRPTTokenMaxPermissions, 10)

	// Expired token retention time, after which tokens will be cleaned up
	c.v.SetDefault(varExpiredTokenRetentionHours, defaultExpiredTokenRetentionHours)

	// Cluster service
	c.v.SetDefault(varShortClusterServiceURL, "http://f8cluster")
	c.v.SetDefault(varClusterRefreshInterval, 5*time.Minute) // 5 minutes

	// User deactivation
	c.v.SetDefault(varUserDeactivationEnabled, defaultUserDeactivationEnabled)
	c.v.SetDefault(varUserDeactivationNotificationEnabled, defaultUserDeactivationNotificationEnabled)
	c.v.SetDefault(varUserDeactivationFetchLimit, defaultUserDeactivationFetchLimit)
	c.v.SetDefault(varUserDeactivationInactivityNotificationPeriodDays, defaultUserDeactivationInactivityNotificationPeriodDays)
	c.v.SetDefault(varUserDeactivationInactivityPeriodDays, defaultUserDeactivationInactivityPeriodDays)
	c.v.SetDefault(varPostDeactivationNotificationDelayMillis, defaultPostDeactivationNotificationDelayMillis)
	c.v.SetDefault(varUserDeactivationWorkerIntervalSeconds, defaultUserDeactivationWorkerIntervalSeconds)
	c.v.SetDefault(varUserDeactivationNotificationWorkerIntervalSeconds, defaultUserDeactivationNotificationWorkerIntervalSeconds)
	c.v.SetDefault(varPodName, defaultPodName)
	c.v.SetDefault(varUserDeactivationWorkerRescheduleDelayHours, defaultUserDeactivationRescheduleDelayHours)

	// Che
	c.v.SetDefault(varCheServiceURL, defaultCheServiceURL)

}

// GetEmailVerifiedRedirectURL returns the url where the user would be redirected to after clicking on email
// verification url
func (c *ConfigurationData) GetEmailVerifiedRedirectURL() string {
	return c.v.GetString(varEmailVerifiedRedirectURL)
}

func (c *ConfigurationData) GetInvitationAcceptedRedirectURL() string {
	return c.v.GetString(varInvitationAcceptedRedirectURL)
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

// IsCleanTestDataEnabled returns `true` if the test data should be cleaned after each test. (default: true)
func (c *ConfigurationData) IsCleanTestDataEnabled() bool {
	return c.v.GetBool(varCleanTestDataEnabled)
}

// IsCleanTestDataErrorReportingRequired returns `true` if there is any error while cleaning test data after each test. (default: true)
func (c *ConfigurationData) IsCleanTestDataErrorReportingRequired() bool {
	return c.v.GetBool(varCleanTestDataErrorReportingRequired)
}

// IsDBLogsEnabled returns `true` if the DB logs (ie, SQL queries) should be output in the console. (default: false)
func (c *ConfigurationData) IsDBLogsEnabled() bool {
	return c.v.GetBool(varDBLogsEnabled)
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
// that is used to verify service account authentication tokens during key rotation.
func (c *ConfigurationData) GetDeprecatedServiceAccountPrivateKey() ([]byte, string) {
	return []byte(c.v.GetString(varServiceAccountPrivateKeyDeprecated)), c.v.GetString(varServiceAccountPrivateKeyIDDeprecated)
}

// GetServiceAccountPrivateKey returns the service account private key and its ID
// that is used to sign service account authentication tokens.
func (c *ConfigurationData) GetServiceAccountPrivateKey() ([]byte, string) {
	return []byte(c.v.GetString(varServiceAccountPrivateKey)), c.v.GetString(varServiceAccountPrivateKeyID)
}

// GetDeprecatedUserAccountPrivateKey returns the deprecated user account private key (if any) and its ID
// that is used to verify user access and refresh tokens during key rotation.
func (c *ConfigurationData) GetDeprecatedUserAccountPrivateKey() ([]byte, string) {
	return []byte(c.v.GetString(varUserAccountPrivateKeyDeprecated)), c.v.GetString(varUserAccountPrivateKeyIDDeprecated)
}

// GetUserAccountPrivateKey returns the user account private key and its ID
// that is used to sign user access and refresh tokens.
func (c *ConfigurationData) GetUserAccountPrivateKey() ([]byte, string) {
	return []byte(c.v.GetString(varUserAccountPrivateKey)), c.v.GetString(varUserAccountPrivateKeyID)
}

// GetAccessTokenExpiresIn returns lifespan of user access tokens generated by Auth in seconds
func (c *ConfigurationData) GetAccessTokenExpiresIn() int64 {
	return c.v.GetInt64(varAccessTokenExpiresIn)
}

// GetRefreshTokenExpiresIn returns lifespan of user refresh tokens generated by Auth in seconds
func (c *ConfigurationData) GetRefreshTokenExpiresIn() int64 {
	return c.v.GetInt64(varRefreshTokenExpiresIn)
}

// GetTransientTokenExpiresIn returns lifespan of transient (short-lived) access token generated by Auth in seconds
func (c *ConfigurationData) GetTransientTokenExpiresIn() int64 {
	return c.v.GetInt64(varTransientTokenExpiresIn)
}

// GetDevModePublicKey returns additional public key and its ID which should be used by the Auth service in Dev Mode
// For example a public key from Keycloak
// Returns false if in in Dev Mode
func (c *ConfigurationData) GetDevModePublicKey() (bool, []byte, string) {
	if c.IsPostgresDeveloperModeEnabled() {
		return true, []byte(devModePublicKey), devModePublicKeyID
	}
	return false, nil, ""
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

// GetOpenShiftClientApiUrl return the default OpenShift cluster client API URL.
// If in a staging env a new user doesn't have the cluster set then this default cluster is used
func (c *ConfigurationData) GetOpenShiftClientApiUrl() string {
	return c.v.GetString(varOSOClientApiUrl)
}

// GetNotApprovedRedirect returns the URL to redirect to if the user is not approved
// May return empty string which means an unauthorized error should be returned instead of redirecting the user
func (c *ConfigurationData) GetNotApprovedRedirect() string {
	return c.v.GetString(varNotApprovedRedirect)
}

// GetOAuthProviderClientSecret returns the oauth client secret (as set via config file or environment variable)
// that is used to make authorized API Calls to the OAuth authentication provider.
func (c *ConfigurationData) GetOAuthProviderClientSecret() string {
	return c.v.GetString(varOAuthProviderClientSecret)
}

// GetOAuthClientID returns the oauth client ID (as set via config file or environment variable)
// that is used to make authorized API Calls to the OAuth authentication provider.
func (c *ConfigurationData) GetOAuthProviderClientID() string {
	return c.v.GetString(varOAuthProviderClientID)
}

// GetPublicOAuthClientID returns the public clientID
func (c *ConfigurationData) GetPublicOAuthClientID() string {
	return c.v.GetString(varPublicOAuthClientID)
}

func (c *ConfigurationData) GetOAuthProviderType() string {
	return c.v.GetString(varOAuthProviderType)
}

// GetOAuthProviderEndpointAuth returns the auth provider endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetOAuthProviderEndpointAuth() string {
	return c.v.GetString(varOAuthProviderEndpointAuth)
}

// GetOAuthProviderEndpointToken returns the auth provider token endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetOAuthProviderEndpointToken() string {
	return c.v.GetString(varOAuthProviderEndpointToken)
}

// GetOAuthProviderEndpointUserInfo returns the auth provider userinfo endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetOAuthProviderEndpointUserInfo() string {
	return c.v.GetString(varOAuthProviderEndpointUserInfo)
}

// GetOAuthProviderEndpointLogout returns the auth provider logout endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetOAuthProviderEndpointLogout() string {
	return c.v.GetString(varOAuthProviderEndpointLogout)
}

// GetNotificationServiceURL returns the URL for the Notification service used for event notification
func (c *ConfigurationData) GetNotificationServiceURL() string {
	return c.v.GetString(varNotificationServiceURL)
}

// GetSentryDSN returns the secret needed to securely communicate with https://errortracking.prod-preview.openshift.io/openshift_io/fabric8-auth/
func (c *ConfigurationData) GetSentryDSN() string {
	return c.v.GetString(varSentryDSN)
}

// GetWITDomainPrefix returns the domain prefix which should be used in requests to the auth service
func (c *ConfigurationData) GetWITDomainPrefix() string {
	return c.v.GetString(varWITDomainPrefix)
}

// GetWITURL returns the WIT URL where WIT is running
// If AUTH_WIT_URL is not set and Auth in not in Dev Mode then we calculate the URL from the Auth Service URL domain
func (c *ConfigurationData) GetWITURL() (string, error) {
	if c.v.IsSet(varWITURL) {
		return c.v.GetString(varWITURL), nil
	}
	if c.IsPostgresDeveloperModeEnabled() {
		return devModeWITURL, nil
	}
	return c.calculateWITURL()
}

// GetTenantServiceURL returns the URL for the Tenant service used by login to initialize OSO tenant space
func (c *ConfigurationData) GetTenantServiceURL() string {
	if c.IsPostgresDeveloperModeEnabled() {
		return devModeTenantServiceURL
	}
	return c.v.GetString(varTenantServiceURL)
}

// GetCheServiceURL returns the URL for the Che service
func (c *ConfigurationData) GetCheServiceURL() string {
	if c.IsPostgresDeveloperModeEnabled() {
		return devModeCheServiceURL
	}
	return c.v.GetString(varCheServiceURL)
}

// GetOSORegistrationAppURL returns the URL for the OpenShift Online Registration App
func (c *ConfigurationData) GetOSORegistrationAppURL() string {
	return c.v.GetString(varOSORegistrationAppURL)
}

// GetOSORegistrationAppAdminUsername returns the admin username used to access OpenShift Online Registration App
func (c *ConfigurationData) GetOSORegistrationAppAdminUsername() string {
	return c.v.GetString(varOSORegistrationAppAdminUsername)
}

// GetOSORegistrationAppAdminToken returns the admin token used to access OpenShift Online Registration App
func (c *ConfigurationData) GetOSORegistrationAppAdminToken() string {
	return c.v.GetString(varOSORegistrationAppAdminToken)
}

func (c *ConfigurationData) calculateWITURL() (string, error) {
	authURL := c.GetAuthServiceURL()
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	host, err := rest.ReplaceDomainPrefix(u.Host, c.GetWITDomainPrefix())
	if err != nil {
		return "", err
	}
	u.Host = host
	return u.String(), nil
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

// GetInternalUsersEmailAddressSuffix returns the email address suffix of employees who can opt-in for the 'internal' features.
func (c *ConfigurationData) GetInternalUsersEmailAddressSuffix() string {
	return c.v.GetString(varInternalUsersEmailAddressSuffix)
}

// GetIgnoreEmailInProd returns regex for checking if the user with such email should be ignored during account provisioning
func (c *ConfigurationData) GetIgnoreEmailInProd() string {
	return c.v.GetString(varIgnoreEmailInProd)
}

// GetPodName returns the name of the pod on which this instance is running
func (c *ConfigurationData) GetPodName() string {
	return c.v.GetString(varPodName)
}

// GetEnvironment returns the current environment application is deployed in
// like 'production', 'prod-preview', 'local', etc as the value of environment variable
// `AUTH_ENVIRONMENT` is set.
func (c *ConfigurationData) GetEnvironment() string {
	return c.v.GetString(varEnvironment)
}

// GetPrivilegeCacheExpirySeconds returns the configured number of seconds after which a create privilege cache entry
// should expire, should it not be marked as stale before this time
func (c *ConfigurationData) GetPrivilegeCacheExpirySeconds() int64 {
	return c.v.GetInt64(varPrivilegeCacheExpirySeconds)
}

// GetRPTTokenMaxPermissions returns the maximum number of permissions that may be stored in an RPT token
func (c *ConfigurationData) GetRPTTokenMaxPermissions() int {
	return c.v.GetInt(varRPTTokenMaxPermissions)
}

func (c *ConfigurationData) GetExpiredTokenRetentionHours() int {
	return c.v.GetInt(varExpiredTokenRetentionHours)
}

// GetUserDeactivationEnabled returns true if the user deactivation worker should be enabled
func (c *ConfigurationData) GetUserDeactivationEnabled() bool {
	return c.v.GetBool(varUserDeactivationEnabled)
}

// GetUserDeactivationNotificationEnabled returns true if the user deactivation notification worker should be enabled
func (c *ConfigurationData) GetUserDeactivationNotificationEnabled() bool {
	return c.v.GetBool(varUserDeactivationNotificationEnabled)
}

// GetUserDeactivationFetchLimit returns the max/limit number of user accounts to deactivate during a worker call
func (c *ConfigurationData) GetUserDeactivationFetchLimit() int {
	return c.v.GetInt(varUserDeactivationFetchLimit)
}

// GetUserDeactivationInactivityNotificationPeriod returns the time duration of inactivity before notifying the user of the imminent account deactivation
func (c *ConfigurationData) GetUserDeactivationInactivityNotificationPeriod() time.Duration {
	return time.Duration(c.v.GetInt(varUserDeactivationInactivityNotificationPeriodDays)) * 24 * time.Hour
}

// GetUserDeactivationInactivityPeriod returns the time duration of inactivity before a user account can be deactivated
func (c *ConfigurationData) GetUserDeactivationInactivityPeriod() time.Duration {
	return time.Duration(c.v.GetInt(varUserDeactivationInactivityPeriodDays)) * 24 * time.Hour
}

// GetPostDeactivationNotificationDelay returns the time duration to wait after notifying another user that her account may be deactivated
// this delay is used to reduce the load on the other services (notification and database) in case there would be
// too many users to notify at once.
func (c *ConfigurationData) GetPostDeactivationNotificationDelay() time.Duration {
	return time.Duration(c.v.GetInt(varPostDeactivationNotificationDelayMillis)) * time.Millisecond
}

// GetUserDeactivationWorkerInterval returns the interval between 2 cycles of the user deactivation worker.
func (c *ConfigurationData) GetUserDeactivationWorkerInterval() time.Duration {
	return time.Duration(c.v.GetInt(varUserDeactivationWorkerIntervalSeconds)) * time.Second
}

// GetUserDeactivationNotificationWorkerInterval returns the interval between 2 cycles of the user deactivation notification worker.
func (c *ConfigurationData) GetUserDeactivationNotificationWorkerInterval() time.Duration {
	return time.Duration(c.v.GetInt(varUserDeactivationNotificationWorkerIntervalSeconds)) * time.Second
}

func (c *ConfigurationData) GetUserDeactivationRescheduleDelay() time.Duration {
	return time.Duration(c.v.GetInt(varUserDeactivationWorkerRescheduleDelayHours)) * time.Hour
}

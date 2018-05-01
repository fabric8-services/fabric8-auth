package configuration

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/fsnotify/fsnotify"
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

	// General
	varHTTPAddress                     = "http.address"
	varMetricsHTTPAddress              = "metrics.http.address"
	varDeveloperModeEnabled            = "developer.mode.enabled"
	varNotApprovedRedirect             = "notapproved.redirect"
	varHeaderMaxLength                 = "header.maxlength"
	varUsersListLimit                  = "users.listlimit"
	defaultConfigFile                  = "config.yaml"
	varValidRedirectURLs               = "redirect.valid"
	varLogLevel                        = "log.level"
	varLogJSON                         = "log.json"
	varEmailVerifiedRedirectURL        = "email.verify.url"
	varInternalUsersEmailAddressSuffix = "internal.users.email.address.domain"
	varKeycloakTestsDisabled           = "keycloak.tests.disabled"
	varIgnoreEmailInProd               = "ignore.email.prod"

	// Postgres
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

	// Public Client ID for logging into Auth service via OAuth2
	varPublicOauthClientID = "public.oauth.client.id"

	// Keycloak
	varKeycloakSecret                   = "keycloak.secret"
	varKeycloakClientID                 = "keycloak.client.id"
	varKeycloakDomainPrefix             = "keycloak.domain.prefix"
	varKeycloakRealm                    = "keycloak.realm"
	varKeycloakTesUserName              = "keycloak.testuser.name"
	varKeycloakTesUserSecret            = "keycloak.testuser.secret"
	varKeycloakTesUser2Name             = "keycloak.testuser2.name"
	varKeycloakTesUser2Secret           = "keycloak.testuser2.secret"
	varKeycloakURL                      = "keycloak.url"
	varKeycloakEndpointAdmin            = "keycloak.endpoint.admin"
	varKeycloakEndpointAuth             = "keycloak.endpoint.auth"
	varKeycloakEndpointToken            = "keycloak.endpoint.token"
	varKeycloakEndpointUserinfo         = "keycloak.endpoint.userinfo"
	varKeycloakEndpointAuthzResourceset = "keycloak.endpoint.authz.resourceset"
	varKeycloakEndpointClients          = "keycloak.endpoint.clients"
	varKeycloakEndpointEntitlement      = "keycloak.endpoint.entitlement"
	varKeycloakEndpointBroker           = "keycloak.endpoint.broker"
	varKeycloakEndpointAccount          = "keycloak.endpoint.account"
	varKeycloakEndpointLogout           = "keycloak.endpoint.logout"

	// Private keys for signing OSIO Serivice Account tokens
	varServiceAccountPrivateKeyDeprecated   = "serviceaccount.privatekey.deprecated"
	varServiceAccountPrivateKeyIDDeprecated = "serviceaccount.privatekeyid.deprecated"
	varServiceAccountPrivateKey             = "serviceaccount.privatekey"
	varServiceAccountPrivateKeyID           = "serviceaccount.privatekeyid"

	// Private keys for signing OSIO Access and Refresh tokens
	varUserAccountPrivateKeyDeprecated   = "useraccount.privatekey.deprecated"
	varUserAccountPrivateKeyIDDeprecated = "useraccount.privatekeyid.deprecated"
	varUserAccountPrivateKey             = "useraccount.privatekey"
	varUserAccountPrivateKeyID           = "useraccount.privatekeyid"

	// Token configuration
	varAccessTokenExpiresIn  = "useraccount.token.access.expiresin"  // In seconds
	varRefreshTokenExpiresIn = "useraccount.token.refresh.expiresin" // In seconds

	// GitHub linking
	varGitHubClientID            = "github.client.id"
	varGitHubClientSecret        = "github.client.secret"
	varGitHubClientDefaultScopes = "github.client.defaultscopes"

	// OSO settings
	varOSOClientApiUrl                 = "oso.client.apiurl" // Default OSO cluster API URL
	varOSORegistrationAppURL           = "oso.regapp.serviceurl"
	varOSORegistrationAppAdminUsername = "oso.regapp.admin.username"
	varOSORegistrationAppAdminToken    = "oso.regapp.admin.token"

	// Cache control
	varCacheControlUsers         = "cachecontrol.users"
	varCacheControlCollaborators = "cachecontrol.collaborators"
	varCacheControlUser          = "cachecontrol.user"

	// Other services URLs
	varWITDomainPrefix        = "wit.domain.prefix"
	varTenantServiceURL       = "tenant.serviceurl"
	varWITURL                 = "wit.url"
	varNotificationServiceURL = "notification.serviceurl"

	// sentry
	varEnvironment = "environment"
	varSentryDSN   = "sentry.dsn"
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
	APIURL                 string `mapstructure:"api-url"`
	ConsoleURL             string `mapstructure:"console-url"` // Optional in oso-clusters.conf
	MetricsURL             string `mapstructure:"metrics-url"` // Optional in oso-clusters.conf
	LoggingURL             string `mapstructure:"logging-url"` // Optional in oso-clusters.conf
	AppDNS                 string `mapstructure:"app-dns"`
	ServiceAccountToken    string `mapstructure:"service-account-token"`
	ServiceAccountUsername string `mapstructure:"service-account-username"`
	TokenProviderID        string `mapstructure:"token-provider-id"`
	AuthClientID           string `mapstructure:"auth-client-id"`
	AuthClientSecret       string `mapstructure:"auth-client-secret"`
	AuthClientDefaultScope string `mapstructure:"auth-client-default-scope"`
	CapacityExhausted      bool   `mapstructure:"capacity-exhausted"` // Optional in oso-clusters.conf ('false' by default)
}

// ConfigurationData encapsulates the Viper configuration object which stores the configuration data in-memory.
type ConfigurationData struct {
	// Main Configuration
	v *viper.Viper

	// Service Account Configuration is a map of service accounts where the key == the service account ID
	sa map[string]ServiceAccount

	// OSO Cluster Configuration is a map of clusters where the key == the OSO cluster API URL
	clusters              map[string]OSOCluster
	clusterConfigFilePath string

	defaultConfigurationError error

	mux sync.RWMutex
}

// NewConfigurationData creates a configuration reader object using configurable configuration file paths
func NewConfigurationData(mainConfigFile string, serviceAccountConfigFile string, osoClusterConfigFile string) (*ConfigurationData, error) {
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

	// Set up the OSO cluster configuration (stored in a separate config file)
	clusterConfigFilePath, err := c.initClusterConfig(osoClusterConfigFile, defaultOsoClusterConfigPath)
	if err != nil {
		return nil, err
	}
	c.clusterConfigFilePath = clusterConfigFilePath

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
	if c.GetKeycloakSecret() == defaultKeycloakSecret {
		c.appendDefaultConfigErrorMessage("default Keycloak client secret is used")
	}
	if c.GetGitHubClientSecret() == defaultGitHubClientSecret {
		c.appendDefaultConfigErrorMessage("default GitHub client secret is used")
	}
	if c.GetValidRedirectURLs() == ".*" {
		c.appendDefaultConfigErrorMessage("no restrictions for valid redirect URLs")
	}
	if c.GetNotificationServiceURL() == "" {
		c.appendDefaultConfigErrorMessage("notification service url is empty")
	}
	if c.GetAccessTokenExpiresIn() < 3*60 {
		c.appendDefaultConfigErrorMessage("too short lifespan of access tokens")
	}
	if c.GetRefreshTokenExpiresIn() < 3*60 {
		c.appendDefaultConfigErrorMessage("too short lifespan of refresh tokens")
	}
	if c.GetOSORegistrationAppURL() == "" {
		c.appendDefaultConfigErrorMessage("OSO Reg App url is empty")
	}
	if c.GetOSORegistrationAppAdminUsername() == "" {
		c.appendDefaultConfigErrorMessage("OSO Reg App admin username is empty")
	}
	if c.GetOSORegistrationAppAdminToken() == "" {
		c.appendDefaultConfigErrorMessage("OSO Reg App admin token is empty")
	}
	if c.GetEnvironment() == "local" || c.GetEnvironment() == "" {
		c.appendDefaultConfigErrorMessage("Environment is empty or set to local")
	}
	if c.GetSentryDSN() == "" {
		c.appendDefaultConfigErrorMessage("Sentry DSN is empty")
	}
	if c.defaultConfigurationError != nil {
		log.WithFields(map[string]interface{}{
			"default_configuration_error": c.defaultConfigurationError.Error(),
		}).Warningln("Default config is used! This is OK in Dev Mode.")
	}

	return c, nil
}

func (c *ConfigurationData) initClusterConfig(osoClusterConfigFile, defaultClusterConfigFile string) (string, error) {
	clusterViper, defaultConfigErrorMsg, usedClusterConfigFile, err := readFromJSONFile(osoClusterConfigFile, defaultClusterConfigFile, osoClusterConfigFileName)
	if err != nil {
		return usedClusterConfigFile, err
	}
	if defaultConfigErrorMsg != nil {
		c.appendDefaultConfigErrorMessage(*defaultConfigErrorMsg)
	}

	var clusterConf osoClusterConfig
	err = clusterViper.Unmarshal(&clusterConf)
	if err != nil {
		return usedClusterConfigFile, err
	}
	c.clusters = map[string]OSOCluster{}
	for _, cluster := range clusterConf.Clusters {
		if cluster.ConsoleURL == "" {
			cluster.ConsoleURL, err = convertAPIURL(cluster.APIURL, "console", "console")
			if err != nil {
				return usedClusterConfigFile, err
			}
		}
		if cluster.MetricsURL == "" {
			cluster.MetricsURL, err = convertAPIURL(cluster.APIURL, "metrics", "")
			if err != nil {
				return usedClusterConfigFile, err
			}
		}
		if cluster.LoggingURL == "" {
			// This is not a typo; the logging host is the same as the console host in current k8s
			cluster.LoggingURL, err = convertAPIURL(cluster.APIURL, "console", "console")
			if err != nil {
				return usedClusterConfigFile, err
			}
		}
		c.clusters[cluster.APIURL] = cluster
	}

	err = c.checkClusterConfig()
	return usedClusterConfigFile, err
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

// checkClusterConfig checks if there is any missing keys or empty values in oso-clusters.conf
func (c *ConfigurationData) checkClusterConfig() error {
	if len(c.clusters) == 0 {
		return errors.New("empty cluster config file")
	}

	err := errors.New("")
	ok := true
	for _, cluster := range c.clusters {
		iVal := reflect.ValueOf(&cluster).Elem()
		typ := iVal.Type()
		for i := 0; i < iVal.NumField(); i++ {
			f := iVal.Field(i)
			tag := typ.Field(i).Tag.Get("mapstructure")
			switch f.Interface().(type) {
			case string:
				if f.String() == "" {
					err = errors.Errorf("%s; key %v is missing in cluster config", err.Error(), tag)
					ok = false
				}
			case bool:
				// Ignore
			default:
				err = errors.Errorf("%s; wrong type of key %v", err.Error(), tag)
				ok = false
			}
		}
	}
	if !ok {
		return err
	}
	return nil
}

func convertAPIURL(apiURL string, newPrefix string, newPath string) (string, error) {
	newURL, err := url.Parse(apiURL)
	if err != nil {
		return "", err
	}
	newHost, err := rest.ReplaceDomainPrefix(newURL.Host, newPrefix)
	if err != nil {
		return "", err
	}
	newURL.Host = newHost
	newURL.Path = newPath
	return newURL.String(), nil
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

func getOSOClusterConfigFile() string {
	envOSOClusterConfigFile, _ := os.LookupEnv("AUTH_OSO_CLUSTER_CONFIG_FILE")
	return envOSOClusterConfigFile
}

// InitializeClusterWatcher initializes a file watcher for the cluster config file
// When the file is updated the configuration synchronously reload the cluster configuration
func (c *ConfigurationData) InitializeClusterWatcher() (func() error, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Remove == fsnotify.Remove {
					time.Sleep(1 * time.Second) // Wait for one second before re-adding and reloading. It might be needed if the file is removed and then re-added in some environments
					err = watcher.Add(event.Name)
					if err != nil {
						log.WithFields(map[string]interface{}{
							"file": event.Name,
						}).Errorln("cluster config was removed but unable to re-add it to watcher")
					}
				}
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Remove == fsnotify.Remove {
					// Reload config if operation is Write or Remove.
					// Both can be part of file update depending on environment and actual operation.
					err := c.reloadClusterConfig()
					if err != nil {
						// Do not crash. Log the error and keep using the existing configuration
						log.WithFields(map[string]interface{}{
							"err":  err,
							"file": event.Name,
							"op":   event.Op.String(),
						}).Errorln("unable to reload cluster config file")
					} else {
						log.WithFields(map[string]interface{}{
							"file": event.Name,
							"op":   event.Op.String(),
						}).Infoln("cluster config file modified and reloaded")
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.WithFields(map[string]interface{}{
					"err": err,
				}).Errorln("cluster config file watcher error")
			}
		}
	}()

	configFilePath, err := pathExists(c.clusterConfigFilePath)
	if err == nil && configFilePath != "" {
		err = watcher.Add(configFilePath)
		log.WithFields(map[string]interface{}{
			"file": c.clusterConfigFilePath,
		}).Infoln("cluster config file watcher initialized")
	} else {
		// OK in Dev Mode
		log.WithFields(map[string]interface{}{
			"file": c.clusterConfigFilePath,
		}).Warnln("cluster config file watcher not initialized for non-existent file")
	}

	return watcher.Close, err
}

func (c *ConfigurationData) reloadClusterConfig() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	_, err := c.initClusterConfig("", c.clusterConfigFilePath)
	return err
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
func (c *ConfigurationData) GetServiceAccounts() map[string]ServiceAccount {
	return c.sa
}

// GetOSOClusters returns a map of OSO cluster configurations by cluster API URL
func (c *ConfigurationData) GetOSOClusters() map[string]OSOCluster {
	// Lock for reading because config file watcher can update cluster configuration
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.clusters
}

// GetOSOClusterByURL returns a OSO cluster configurations by matching URL
// Regardless of trailing slashes if cluster API URL == "https://api.openshift.com"
// or "https://api.openshift.com/" it will match any "https://api.openshift.com*"
// like "https://api.openshift.com", "https://api.openshift.com/", or "https://api.openshift.com/patch"
// Returns nil if no matching API URL found
func (c *ConfigurationData) GetOSOClusterByURL(url string) *OSOCluster {
	// Lock for reading because config file watcher can update cluster configuration
	c.mux.RLock()
	defer c.mux.RUnlock()

	for apiURL, cluster := range c.clusters {
		if strings.HasPrefix(rest.AddTrailingSlashToURL(url), apiURL) {
			return &cluster
		}
	}

	return nil
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
	c.v.SetDefault(varUserAccountPrivateKey, DefaultUserAccountPrivateKey)
	c.v.SetDefault(varUserAccountPrivateKeyID, defaultUserAccountPrivateKeyID)
	var in30Days int64
	in30Days = 30 * 24 * 60 * 60
	c.v.SetDefault(varAccessTokenExpiresIn, in30Days)
	c.v.SetDefault(varRefreshTokenExpiresIn, in30Days)
	c.v.SetDefault(varKeycloakClientID, defaultKeycloakClientID)
	c.v.SetDefault(varKeycloakSecret, defaultKeycloakSecret)
	c.v.SetDefault(varPublicOauthClientID, defaultPublicOauthClientID)
	c.v.SetDefault(varKeycloakDomainPrefix, defaultKeycloakDomainPrefix)
	c.v.SetDefault(varKeycloakTesUserName, defaultKeycloakTesUserName)
	c.v.SetDefault(varKeycloakTesUserSecret, defaultKeycloakTesUserSecret)
	c.v.SetDefault(varGitHubClientID, "c6a3a6280e9650ba27d8")
	c.v.SetDefault(varGitHubClientSecret, defaultGitHubClientSecret)
	c.v.SetDefault(varGitHubClientDefaultScopes, "admin:repo_hook read:org public_repo read:user")
	c.v.SetDefault(varOSOClientApiUrl, "https://api.starter-us-east-2.openshift.com")

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

	// On email successful/failed verification, redirect to this page.
	c.v.SetDefault(varEmailVerifiedRedirectURL, "https://prod-preview.openshift.io/_home")

	// default email address suffix
	c.v.SetDefault(varInternalUsersEmailAddressSuffix, "@redhat.com")

	// Regex to be used to check if the user with such email should be ignored during account provisioning
	c.v.SetDefault(varIgnoreEmailInProd, ".+\\+preview.*\\@redhat\\.com")

	// prod-preview or prod
	c.v.SetDefault(varEnvironment, "local")
}

// GetEmailVerifiedRedirectURL returns the url where the user would be redirected to after clicking on email
// verification url
func (c *ConfigurationData) GetEmailVerifiedRedirectURL() string {
	return c.v.GetString(varEmailVerifiedRedirectURL)
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

// GetUserAccountPrivateKey returns the service account private key and its ID
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

// GetKeycloakEndpointAuth returns the keycloak auth endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAuth(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointAuth, "auth")
}

// GetKeycloakEndpointToken returns the keycloak token endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointToken(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointToken, "token")
}

// GetKeycloakEndpointUserInfo returns the keycloak userinfo endpoint set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
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

// GetSentryDSN returns the secret needed to securely communicate with https://errortracking.prod-preview.openshift.io/openshift_io/fabric8-auth/
func (c *ConfigurationData) GetSentryDSN() string {
	return c.v.GetString(varSentryDSN)
}

// GetKeycloakEndpointAdmin returns the <keycloak>/realms/admin/<realm> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAdmin(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAdmin, "auth/admin/realms/"+c.GetKeycloakRealm())
}

// GetKeycloakEndpointUsers returns the <keycloak>/realms/admin/<realm>/users endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointUsers(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAdmin, "auth/admin/realms/"+c.GetKeycloakRealm()+"/users")

}

// GetKeycloakEndpointIDP returns the <keycloak>/realms/admin/<realm>/users/USER_ID/federated-identity/rhd endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointLinkIDP(req *goa.RequestData, id string, idp string) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAdmin, "auth/admin/realms/"+c.GetKeycloakRealm()+"/users/"+id+"/federated-identity/"+idp)
}

// GetKeycloakEndpointAuthzResourceset returns the <keycloak>/realms/<realm>/authz/protection/resource_set endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAuthzResourceset(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAuthzResourceset, "auth/realms/"+c.GetKeycloakRealm()+"/authz/protection/resource_set")
}

// GetKeycloakEndpointClients returns the <keycloak>/admin/realms/<realm>/clients endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointClients(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointClients, "auth/admin/realms/"+c.GetKeycloakRealm()+"/clients")
}

// GetKeycloakEndpointEntitlement returns the <keycloak>/realms/<realm>/authz/entitlement/<clientID> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointEntitlement(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointEntitlement, "auth/realms/"+c.GetKeycloakRealm()+"/authz/entitlement/"+c.GetKeycloakClientID())
}

// GetKeycloakEndpointBroker returns the <keycloak>/realms/<realm>/authz/entitlement/<clientID> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the default endpoint will be returned.
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
// If nothing set then in Dev environment the default endpoint will be returned.
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
			// Devmode is enabled. Calculate the URL endpoint using the devmode Keycloak URL
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

// GetInternalUsersEmailAddressSuffix returns the email address suffix of employees who can opt-in for the 'internal' features.
func (c *ConfigurationData) GetInternalUsersEmailAddressSuffix() string {
	return c.v.GetString(varInternalUsersEmailAddressSuffix)
}

// GetIgnoreEmailInProd returns regex for checking if the user with such email should be ignored during account provisioning
func (c *ConfigurationData) GetIgnoreEmailInProd() string {
	return c.v.GetString(varIgnoreEmailInProd)
}

// GetEnvironment returns the current environment application is deployed in
// like 'production', 'prod-preview', 'local', etc as the value of environment variable
// `AUTH_ENVIRONMENT` is set.
func (c *ConfigurationData) GetEnvironment() string {
	return c.v.GetString(varEnvironment)
}

package provider

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	GITHUB            = "github"
	DEFAULT_OPENSHIFT = "openshift-v3"
)

// ExternalProviderConfiguration exposes the relevant configuration information for external provider oauth
type ExternalProviderConfiguration interface {
	GetGithubClientID() string
	GetGithubSecret() string
	GetOpenshiftTenantMasterURL() string
	GetOpenShiftSecret() string
	GetOpenShiftClientID() string
}

// OAuthConfigurationService provides access to the oauth configs
type OAuthConfigurationService interface {
	GetGithubOAuthConfiguration() *oauth2.Config
	GetOpenShiftConfiguration(url string) *oauth2.Config
}

// OAuthConfiguration describes the possible oauth configurations
type OAuthConfiguration struct {
	AllConfiguration map[string]oauth2.Config
}

func (c *OAuthConfiguration) GetGithubOAuthConfiguration() *oauth2.Config {
	config, found := c.AllConfiguration[GITHUB]
	if found {
		return &config
	}
	return nil
}

func (c *OAuthConfiguration) GetOpenShiftConfiguration(url string) *oauth2.Config {
	config, found := c.AllConfiguration[url]
	if found {
		return &config
	}
	return nil
}

// InitializeOAuthConfiguration reads the configuration and prepares the map of oauth configuration
func InitializeOAuthConfiguration(c ExternalProviderConfiguration) *OAuthConfiguration {

	OPENSHIFT := c.GetOpenshiftTenantMasterURL()

	osoOAuthEndpoint := oauth2.Endpoint{
		// TODO : move to Configuration
		AuthURL:  OPENSHIFT + "/oauth/authorize",
		TokenURL: OPENSHIFT + "/oauth/access_token",
	}

	allConfig := map[string]oauth2.Config{
		GITHUB: oauth2.Config{
			ClientID:     c.GetGithubClientID(),
			ClientSecret: c.GetGithubSecret(),
			Scopes:       []string{"user", "gist", "read:org", "admin:repo_hook"},
			Endpoint:     github.Endpoint,
		},
		OPENSHIFT: oauth2.Config{
			ClientID:     c.GetOpenShiftClientID(),
			ClientSecret: c.GetOpenShiftSecret(),
			Scopes:       []string{"user:full"},
			Endpoint:     osoOAuthEndpoint,
		},
		DEFAULT_OPENSHIFT: oauth2.Config{
			ClientID:     c.GetOpenShiftClientID(),
			ClientSecret: c.GetOpenShiftSecret(),
			Scopes:       []string{"user:full"},
			Endpoint:     osoOAuthEndpoint,
		},
		// Add more for multiple-clusters
	}

	return &OAuthConfiguration{
		AllConfiguration: allConfig,
	}
}

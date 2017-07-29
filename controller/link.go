package controller

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/provider"
	"github.com/goadesign/goa"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// LinkController implements the link resource.
type LinkController struct {
	*goa.Controller
	Configuration           LoginConfiguration
	Identities              account.IdentityRepository
	Users                   account.UserRepository
	ExternalTokenRepository provider.ExternalProviderTokenRepository
}

// NewLinkController creates a link controller.
func NewLinkController(service *goa.Service, configuration LoginConfiguration, identities account.IdentityRepository, users account.UserRepository, externalTokenRepository provider.ExternalProviderTokenRepository) *LinkController {
	return &LinkController{
		Controller:    service.NewController("link"),
		Configuration: configuration,
		Identities:    identities,
		Users:         users,
		ExternalTokenRepository: externalTokenRepository,
	}
}

// Link links identity provider(s) to the user's account
func (c *LinkController) Link(ctx *app.LinkLinkContext) error {
	// TODO: Write code in a generic way to use the appropriate oauth
	// service based on provider

	// TODO: move endpoints/cliendID/Secret to configuration framework.
	var oauthConfig *oauth2.Config
	if ctx.Provider == nil || *ctx.Provider == "openshift-v3" {
		osoOAuthEndpoint := oauth2.Endpoint{
			AuthURL:  "https://192.168.42.59:8443/oauth/authorize",
			TokenURL: "https://192.168.42.59:8443/oauth/access_token",
		}
		oauthConfig = &oauth2.Config{
			ClientID:     "openshift-v3-authentication",
			ClientSecret: "1234",
			Scopes:       []string{"user:full"},
			Endpoint:     osoOAuthEndpoint,
		}
	} else if *ctx.Provider == "github" {
		oauthConfig = &oauth2.Config{
			ClientID:     c.Configuration.GetGithubClientID(),
			ClientSecret: c.Configuration.GetGithubSecret(),
			Scopes:       []string{"user", "gist", "read:org", "admin:repo_hook"},
			Endpoint:     github.Endpoint,
		}
	}

	// TODO: feels a bit uncomfortable that new oauthService objects are being initialized per req.
	genericOAuthService := provider.NewGenericOAuth(oauthConfig, c.Identities, c.Users, c.ExternalTokenRepository)
	return genericOAuthService.Perform(ctx)
}

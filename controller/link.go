package controller

import (
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/provider"
	"github.com/goadesign/goa"
	"golang.org/x/oauth2"
)

// LinkController implements the link resource.
type LinkController struct {
	*goa.Controller
	Configuration                LoginConfiguration
	Identities                   account.IdentityRepository
	Users                        account.UserRepository
	ExternalTokenRepository      provider.ExternalProviderTokenRepository
	AllOAuthConfigurationService provider.OAuthConfigurationService
}

// NewLinkController creates a link controller.
func NewLinkController(service *goa.Service, configuration LoginConfiguration, identities account.IdentityRepository, users account.UserRepository, externalTokenRepository provider.ExternalProviderTokenRepository, allOAuthConfig provider.OAuthConfigurationService) *LinkController {
	return &LinkController{
		Controller:    service.NewController("link"),
		Configuration: configuration,
		Identities:    identities,
		Users:         users,
		ExternalTokenRepository:      externalTokenRepository,
		AllOAuthConfigurationService: allOAuthConfig,
	}
}

// Link links identity provider(s) to the user's account
func (c *LinkController) Link(ctx *app.LinkLinkContext) error {

	var oauthConfig *oauth2.Config
	if ctx.Provider == nil {
		defaultProvider := provider.GITHUB
		ctx.Provider = &defaultProvider
	}

	if *ctx.Provider == provider.GITHUB { // default
		oauthConfig = c.AllOAuthConfigurationService.GetGithubOAuthConfiguration()
	} else if ctx.Provider != nil {
		// everything else should be some OSO cluster.
		// TODO: have some url pattern validation
		oauthConfig = c.AllOAuthConfigurationService.GetOpenShiftConfiguration(*ctx.Provider)
	}

	if oauthConfig == nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("provider", *ctx.Provider).Expected("github/openshift-v3"))
	}
	genericOAuthService := provider.NewGenericOAuth(oauthConfig, c.Identities, c.Users, c.ExternalTokenRepository)
	return genericOAuthService.Perform(ctx)
}

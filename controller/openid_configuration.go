package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/goadesign/goa"
)

// OpenidConfigurationController implements the openid_configuration resource.
type OpenidConfigurationController struct {
	*goa.Controller
}

// NewOpenidConfigurationController creates a openid_configuration controller.
func NewOpenidConfigurationController(service *goa.Service) *OpenidConfigurationController {
	return &OpenidConfigurationController{Controller: service.NewController("OpenidConfigurationController")}
}

// Show runs the show action.
func (c *OpenidConfigurationController) Show(ctx *app.ShowOpenidConfigurationContext) error {

	issuer := rest.AbsoluteURL(ctx.RequestData, "")
	authorizationEndpoint := rest.AbsoluteURL(ctx.RequestData, client.AuthorizeAuthorizePath())
	tokenEndpoint := rest.AbsoluteURL(ctx.RequestData, client.ExchangeTokenPath())
	userinfoEndpoint := rest.AbsoluteURL(ctx.RequestData, client.ShowUserinfoPath())
	logoutEndpoint := rest.AbsoluteURL(ctx.RequestData, client.LogoutLogoutPath())
	jwksURI := rest.AbsoluteURL(ctx.RequestData, client.KeysTokenPath())

	authOpenIDConfiguration := &app.OpenIDConfiguration{
		// REQUIRED properties
		Issuer:                 &issuer,
		AuthorizationEndpoint:  &authorizationEndpoint,
		TokenEndpoint:          &tokenEndpoint,
		EndSessionEndpoint:     &logoutEndpoint,
		ResponseTypesSupported: []string{"code"},
		JwksURI:                &jwksURI,

		// subject_types_supported REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include pairwise and public.
		// A Subject Identifier is a locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client.
		// http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
		// subject ==  identity
		SubjectTypesSupported: []string{"public"},
		// id_token_signing_alg_values_supported REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
		// The algorithm RS256 MUST be included. The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow).
		IDTokenSigningAlgValuesSupported: []string{"RS256"},

		// RECOMMENDED properties
		UserinfoEndpoint: &userinfoEndpoint,
		ScopesSupported:  []string{"openid", "offline_access"},
		ClaimsSupported:  []string{"sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email"},

		// OPTIONAL properties
		GrantTypesSupported: []string{"authorization_code", "refresh_token", "client_credentials"},
		// client_secret_post for client_credentials grant_type
		// client_secre_jwt for authorizatoin_code grant_type
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_jwt"},
		// response_modes_supported
	}

	return ctx.OK(authOpenIDConfiguration)
}

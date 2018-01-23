package controller

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/goadesign/goa"
)

// OpenidConfigurationController implements the openid_configuration resource.
type OpenidConfigurationController struct {
	*goa.Controller
	configuration LoginConfiguration
}

// NewOpenidConfigurationController creates a openid_configuration controller.
func NewOpenidConfigurationController(service *goa.Service, configuration LoginConfiguration) *OpenidConfigurationController {
	return &OpenidConfigurationController{Controller: service.NewController("OpenidConfigurationController"), configuration: configuration}
}

// Show runs the show action.
func (c *OpenidConfigurationController) Show(ctx *app.ShowOpenidConfigurationContext) error {

	// Getting Keycloak's /.well-known/openid-configuration
	keycloakOpenIDConfigurationEndpoint := c.configuration.GetKeycloakURL() + "/auth/realms/" + c.configuration.GetKeycloakRealm() + "/.well-known/openid-configuration"
	response, err := http.Get(keycloakOpenIDConfigurationEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{}, "request to achieve openid-configuration of keycloak failed")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err.Error())
	}
	keycloakOpenIDConfiguration := &app.OpenIDConfiguration{}
	err = json.Unmarshal(body, keycloakOpenIDConfiguration)
	if err != nil {
		log.Error(ctx, map[string]interface{}{}, "unable to unmashal to json")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	issuer := rest.AbsoluteURL(ctx.RequestData, "")
	authorizationEndpoint := rest.AbsoluteURL(ctx.RequestData, client.AuthorizeAuthorizePath())
	tokenEndpoint := rest.AbsoluteURL(ctx.RequestData, client.ExchangeTokenPath())
	logoutEndpoint := rest.AbsoluteURL(ctx.RequestData, client.LogoutLogoutPath())
	jwksURI := c.configuration.GetKeycloakEndpointCerts()

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
		IDTokenSigningAlgValuesSupported: keycloakOpenIDConfiguration.IDTokenSigningAlgValuesSupported, //[]string{"RS256"},

		// RECOMMENDED properties
		// userinfo_endpoint : We don't have a OpenID compliant userinfo_endpoint
		ScopesSupported: keycloakOpenIDConfiguration.ScopesSupported, // ["openid","offline_access"]
		ClaimsSupported: []string{"email", "full_name", "email", "image_url", "bio", "url", "company", "cluster", "email_verified", "email_private", "feature_level"},

		// OPTIONAL properties
		GrantTypesSupported: []string{"authorization_code", "refresh_token", "client_credentials"},
		// response_modes_supported
		// token_endpoint_auth_methods_supported
	}

	return ctx.OK(authOpenIDConfiguration)
}

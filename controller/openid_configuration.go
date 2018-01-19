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
	// OpenidConfigurationController_Show: start_implement

	// Put your logic here

	// OpenidConfigurationController_Show: end_implement
	/*
			a.Attribute("issuer", d.String, "")
		a.Attribute("authorization_endpoint", d.String, "")
		a.Attribute("token_endpoint", d.String, "")
		a.Attribute("token_endpoint_auth_methods_supported", a.ArrayOf(d.String), "")
		a.Attribute("token_endpoint_auth_signing_alg_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("userinfo_endpoint", d.String, "")
		a.Attribute("check_session_iframe", d.String, "")
		a.Attribute("end_session_endpoint", d.String, "")
		a.Attribute("jwks_uri", d.String, "")
		a.Attribute("registration_endpoint", d.String, "")
		a.Attribute("scopes_supported", a.ArrayOf(d.String), "")
		a.Attribute("response_types_supported", a.ArrayOf(d.String), "")
		a.Attribute("acr_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("subject_types_supported", a.ArrayOf(d.String), "")
		a.Attribute("userinfo_signing_alg_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("userinfo_encryption_alg_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("userinfo_encryption_enc_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("id_token_signing_alg_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("id_token_encryption_alg_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("id_token_encryption_enc_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("request_object_signing_alg_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("display_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("claim_types_supported", a.ArrayOf(d.String), "")
		a.Attribute("claims_supported", a.ArrayOf(d.String), "")
		a.Attribute("claim_types_supported", a.ArrayOf(d.String), "")
		a.Attribute("claims_parameter_supported", d.Boolean, "")
		a.Attribute("service_documentation", d.String, "")
		a.Attribute("ui_locales_supported", a.ArrayOf(d.String), "")
	*/

	authorizationEndpoint := rest.AbsoluteURL(ctx.RequestData, client.AuthorizeAuthorizePath())
	tokenEndpoint := rest.AbsoluteURL(ctx.RequestData, client.ExchangeTokenPath())

	res := &app.OpenIDConfiguration{
		AuthorizationEndpoint: &authorizationEndpoint,
		TokenEndpoint:         &tokenEndpoint,
	}

	return ctx.OK(res)
}

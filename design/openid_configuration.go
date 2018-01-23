package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

// configuration represents openid-configuration

var openIDConfiguration = a.MediaType("application/vnd.openIDConfiguration+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("OpenIDConfiguration")
	a.Description("Indentity Provider Configuration. It list all endpoints supported by Auth Service")
	a.Attributes(func() {
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
		a.Attribute("grant_types_supported", a.ArrayOf(d.String), "")
	})
	a.View("default", func() {
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
		a.Attribute("grant_types_supported", a.ArrayOf(d.String), "")
	})
})

var _ = a.Resource("openid_configuration", func() {
	a.BasePath("/.well-known")

	a.Action("show", func() {
		a.Routing(
			a.GET("/openid-configuration"),
		)
		a.Description("Show Indentity Provider Configuration. It list all endpoints supported by Auth Service")

		// Check if "NotModified" can be used here
		// a.UseTrait("conditional")
		// a.Response(d.NotModified)
		a.Response(d.OK, openIDConfiguration)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})

})

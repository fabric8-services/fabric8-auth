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
		a.Attribute("issuer", d.String, "REQUIRED. URL using the https scheme with no query or fragment component that the OpenID Provider asserts as its Issuer Identifier. If Issuer discovery is supported, this value MUST be identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.")
		a.Attribute("authorization_endpoint", d.String, "REQUIRED. URL of the OpenID Provider's OAuth 2.0 Authorization Endpoint")
		a.Attribute("token_endpoint", d.String, "URL of the OpenID Provider's OAuth 2.0 Token Endpoint. This is REQUIRED unless only the Implicit Flow is used.")
		a.Attribute("end_session_endpoint", d.String, "URL of the OpenID Provider's Logout Endpoint")
		a.Attribute("jwks_uri", d.String, "REQUIRED. URL of the OpenID Provider's JSON Web Key Set [JWK] document. This contains the signing key(s) the Relying Parties uses to validate signatures from the OpenID Provider. The JWK Set MAY also contain the Server's encryption key(s), which are used by Relying Parties to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage. ")
		a.Attribute("response_types_supported", a.ArrayOf(d.String), "REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OpenID Provider supports.")
		a.Attribute("subject_types_supported", a.ArrayOf(d.String), "REQUIRED. JSON array containing a list of the Subject Identifier types that this OpenID Provider supports. Valid types include pairwise and public.")
		a.Attribute("id_token_signing_alg_values_supported", a.ArrayOf(d.String), "REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OpenID Provider for the ID Token to encode the Claims in a JWT. The algorithm RS256 MUST be included.")
		a.Attribute("grant_types_supported", a.ArrayOf(d.String), "OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types.")
		a.Attribute("scopes_supported", a.ArrayOf(d.String), "RECOMMENDED. JSON array containing a list of the OAuth 2.0 scope values that this server supports. The server MUST support the `openid` scope value.")
		a.Attribute("claims_supported", a.ArrayOf(d.String), "RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.")
		a.Attribute("token_endpoint_auth_methods_supported", a.ArrayOf(d.String), "OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint. The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt etc.")
	})
	a.View("default", func() {
		a.Attribute("issuer", d.String, "")
		a.Attribute("authorization_endpoint", d.String, "")
		a.Attribute("token_endpoint", d.String, "")
		a.Attribute("end_session_endpoint", d.String, "")
		a.Attribute("jwks_uri", d.String, "")
		a.Attribute("response_types_supported", a.ArrayOf(d.String), "")
		a.Attribute("subject_types_supported", a.ArrayOf(d.String), "")
		a.Attribute("id_token_signing_alg_values_supported", a.ArrayOf(d.String), "")
		a.Attribute("grant_types_supported", a.ArrayOf(d.String), "")
		a.Attribute("scopes_supported", a.ArrayOf(d.String), "")
		a.Attribute("claims_supported", a.ArrayOf(d.String), "")
		a.Attribute("token_endpoint_auth_methods_supported", a.ArrayOf(d.String), "")
	})
})

var _ = a.Resource("openid_configuration", func() {
	a.BasePath("/.well-known")

	a.Action("show", func() {
		a.Routing(
			a.GET("/openid-configuration"),
		)
		a.Description("Show Indentity Provider Configuration. It lists all endpoints supported by Auth Service")

		a.Response(d.OK, openIDConfiguration)
	})

})

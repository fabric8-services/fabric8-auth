package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

// AuthorizationCode
var authorizationCode = a.MediaType("application/vnd.authorizationCode+json", func() {
	a.TypeName("AuthorizationCode")
	a.Description("authorization_code from keycloak")
	a.Attributes(func() {
		a.Attribute("code", d.String, "authorization_code from keycloak")
		a.Attribute("state", d.UUID, "")
		a.Required("code", "state")
	})

	a.View("default", func() {
		a.Attribute("code")
		a.Attribute("state")
		a.Required("code", "state")
	})

})

var _ = a.Resource("login", func() {

	a.BasePath("/login")

	a.Action("login", func() {
		a.Routing(
			a.GET(""),
		)
		a.Params(func() {
			a.Param("link", d.Boolean, "If true then link all available Identity Providers to the user account after successful login")
			a.Param("redirect", d.String, "URL to be redirected to after successful login. If not set then will redirect to the referrer instead.")
			a.Param("scope", d.String, func() {
				a.Enum("offline_access")
				a.Description("If scope=offline_access then an offline token will be issued instead of a regular refresh token")
			})
			a.Param("api_client", d.String, "The name of the api client which is requesting a token")
		})
		a.Description("Login user")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})
})

var _ = a.Resource("authorize", func() {

	a.BasePath("/authorize")

	a.Action("authorize", func() {
		a.Routing(
			a.GET(""),
		)
		a.Params(func() {
			a.Param("response_type", d.String, func() {
				a.Enum("code")
				a.Description("response_type=code for grant_type authorization_code")
			})
			a.Param("client_id", d.String, "")
			a.Param("redirect_uri", d.String, "This is where authorization provider will send authorization_code")
			a.Param("scope", d.String, "")
			a.Param("state", d.UUID, "")
			a.Param("code", d.String, "authorization_code")
			a.Param("api_client", d.String, "The name of the api client which is requesting a token")
			a.Required("state")
		})
		a.Description("Authorize service client")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})
})

var _ = a.Resource("logout", func() {

	a.BasePath("/logout")

	a.Action("logout", func() {
		a.Routing(
			a.GET(""),
		)
		a.Params(func() {
			a.Param("redirect", d.String, "URL to be redirected to after successful logout. If not set then will redirect to the referrer instead.")
		})
		a.Description("Logout user")
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})
})

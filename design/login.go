package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

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

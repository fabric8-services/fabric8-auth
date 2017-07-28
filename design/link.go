package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("link", func() {

	a.BasePath("/link")

	a.Action("link", func() {
		//a.Security("jwt")  // TEMPORARY, for testing.
		a.Routing(
			a.GET(""),
		)
		a.Params(func() {
			a.Param("provider", d.String, "Identity Provider name to link to the user's account. If not set then link all available providers.")
			a.Param("redirect", d.String, "URL to be redirected to after successful account linking. If not set then will redirect to the referrer instead.")
		})
		a.Description("Link an Identity Provider account to the user account")
		a.Response(d.TemporaryRedirect)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})

	a.Action("session", func() {
		a.Routing(
			a.GET("/session"),
		)
		a.Params(func() {
			a.Param("provider", d.String, "Identity Provider name to link to the user's account. If not set then link all available providers.")
			a.Param("redirect", d.String, "URL to be redirected to after successful account linking. If not set then will redirect to the referrer instead.")
			a.Param("sessionState", d.String, "Session state")
		})
		a.Description("Link an Identity Provider account to the user account represented by user's session. This endpoint is to be used for auto linking during login.")
		a.Response(d.TemporaryRedirect)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})

	a.Action("callback", func() {
		a.Routing(
			a.GET("/callback"),
		)
		a.Params(func() {
			a.Param("state", d.String, "State generated by the link request")
			a.Param("next", d.String, "Next provider to be linked. If not set then linking is complete.")
			a.Param("sessionState", d.String, "Session state")
		})
		a.Description("Callback from Keyckloak when Identity Provider account successfully linked to the user account")
		a.Response(d.TemporaryRedirect)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})
})

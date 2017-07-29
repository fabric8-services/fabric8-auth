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
})

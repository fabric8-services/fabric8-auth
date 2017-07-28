package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("provider", func() {
	a.BasePath("/provider")

	a.Action("get", func() {
		a.Security("jwt")
		a.Routing(
			a.GET(":provider/token"),
		)
		a.Params(func() {
			a.Param("provider", d.String, "Identity Provider - example github or OSO ")
		})
		a.Description("Retrieve stored access token issued by Identity Provider")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.OK, func() {
			a.Media(AuthToken)
		})
	})
})

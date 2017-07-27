package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("broker", func() {
	a.BasePath("/broker")

	a.Action("get", func() {
		a.Routing(
			a.GET("/:provider"),
		)
		a.Params(func() {
			a.Param("provider", d.String, "Identity Provider - example github or OSO ")
		})
		a.Description("Retrieve stored access token issued by Identity Provider")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})

	a.Action("refresh", func() {
		a.Routing(
			a.POST("/:provider/refresh"),
		)
		a.Payload(refreshToken)
		a.Description("Refresh access token issued by Identity Provider")
		a.Response(d.OK, func() {
			a.Media(AuthToken)
		})
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})
})

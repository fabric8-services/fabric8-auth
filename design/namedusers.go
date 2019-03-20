package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("namedusers", func() {
	a.BasePath("/namedusers")

	a.Action("ban", func() {
		a.Security("jwt")
		a.Routing(
			a.PATCH("/:username/ban"),
		)
		a.Description("ban the user")
		a.Params(func() {
			a.Param("username", d.String, "Username")
		})
		a.Response(d.OK, func() {
			a.Media(showUser)
		})
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
	})
	// `deprovision` is now a deprecated endpoint, replaced by `ban`, with the same URL args template.
	a.Action("deprovision", func() {
		a.Security("jwt")
		a.Routing(
			a.PATCH("/:username/deprovision"),
		)
		a.Description("deprovision the user")
		a.Params(func() {
			a.Param("username", d.String, "Username")
		})
		a.Response(d.OK, func() {
			a.Media(showUser)
		})
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
	})

	a.Action("deactivate", func() {
		a.Security("jwt")
		a.Routing(
			a.PATCH("/:username/deactivate"),
		)
		a.Description("deactivate the user")
		a.Params(func() {
			a.Param("username", d.String, "Username")
		})
		a.Response(d.OK, func() {
			a.Media(showUser)
		})
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
	})
})

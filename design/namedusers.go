package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("namedusers", func() {
	a.BasePath("/namedusers")
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
})

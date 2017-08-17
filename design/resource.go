package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("resource", func() {

	a.BasePath("/resource")

	a.Action("register", func() {
		a.Routing(
			a.POST(""),
		)
		a.Description("Register a new resource")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Created, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})

	a.Action("read", func() {
		a.Routing(
			a.GET("/:resourceId"),
		)
		a.Params(func() {
			a.Param("resourceId", d.String, "The identifier of the resource to read")
		})
		a.Description("Read a specific resource")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
	})

	a.Action("update", func() {
		a.Routing(
			a.PUT("/:resourceId"),
		)
		a.Params(func() {
			a.Param("resourceId", d.String, "Identifier of the resource to update")
		})
		a.Description("Update the details of the specified resource")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
	})

	a.Action("delete", func() {
		a.Routing(
			a.DELETE("/:resourceId"),
		)
		a.Params(func() {
			a.Param("resourceId", d.String, "Identifier of the resource to delete")
		})
		a.Description("Delete a resource")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
	})

	a.Action("list", func() {
		a.Routing(
			a.GET(""),
		)
		a.Description("List all resources")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})
})

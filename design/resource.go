package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("resource", func() {

	a.BasePath("/resource")

	a.DefaultMedia(ResourceMedia)

	a.Action("register", func() {
		a.Routing(
			a.POST(""),
		)
		a.Description("Register a new resource")
		a.Payload(ResourceMedia)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Created, RegisterResourceMedia)
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
		a.Response(d.Forbidden, JSONAPIErrors)
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

})

// ResourceMedia represents a protected resource
var ResourceMedia = a.MediaType("application/vnd.resource+json", func() {
	a.Description("A Protected Resource")
	a.Attributes(func() {
		a.Attribute("resource_scopes", a.ArrayOf(d.String), "The valid scopes for this resource")
		a.Attribute("icon_uri", d.String, "The URI containing the icon for the resource")
		a.Attribute("name", d.String, "The name of the resource")
		a.Attribute("description", d.String, "Description of the resource")
		a.Attribute("type", d.String, "The type of resource")
		a.Attribute("parent_resource_id", d.String, "The parent resource (of the same type) to which this resource belongs")
		a.Attribute("resource_id", d.String, "The identifier for this resource. If left blank, one will be generated")
		a.Required("name", "type")
	})
	a.View("default", func() {
		a.Attribute("resource_scopes")
		a.Attribute("icon_uri")
		a.Attribute("name")
		a.Attribute("description")
		a.Attribute("type")
		a.Attribute("parent_resource_id")
		a.Attribute("resource_id")
	})
})

var RegisterResourceMedia = a.MediaType("application/vnd.register_resource+json", func() {
	a.Description("Response returned when a resource is registered")
	a.Attributes(func() {
		a.Attribute("_id", d.String, "The identifier for the registered resource")
	})
	a.View("default", func() {
		a.Attribute("_id")
	})
})


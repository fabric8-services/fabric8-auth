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
		a.Payload(RegisterResourceMedia)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Created, RegisterResourceResponseMedia)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
	})

	a.Action("show", func() { // action named "show" will have an associated, generated `href` utility function
		a.Routing(
			a.GET("/:resourceId"),
		)
		a.Params(func() {
			a.Param("resourceId", d.String, "The identifier of the resource to read")
		})
		a.Description("Shows a specific resource")
		a.Response(d.OK, ResourceMedia)
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
		a.Response(d.NoContent)
	})

	a.Action("scopes", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/:resourceId/scopes"),
		)
		a.Params(func() {
			a.Param("resourceId", d.String, "Identifier of the resource to list scopes for")
		})
		a.Description("List scopes for a resource")
		a.Response(d.OK, ResourceScopesData)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
	})

})

// ResourceMedia represents a protected resource
var ResourceMedia = a.MediaType("application/vnd.resource+json", func() {
	a.Description("A Protected Resource")
	a.Attributes(func() {
		a.Attribute("resource_scopes", a.ArrayOf(d.String), "The valid scopes for this resource")
		a.Attribute("type", d.String, "The type of resource")
		a.Attribute("parent_resource_id", d.String, "The parent resource (of the same type) to which this resource belongs")
		a.Attribute("resource_id", d.String, "The identifier for this resource. If left blank, one will be generated")
	})
	a.View("default", func() {
		a.Attribute("resource_scopes")
		a.Attribute("type")
		a.Attribute("parent_resource_id")
		a.Attribute("resource_id")
	})
})

var ResourceScopesData = a.MediaType("application/vnd.resource_scopes_data+json", func() {
	a.Description("Resource scopes data wrapper")
	a.Attributes(func() {
		a.Attribute("data", a.ArrayOf(ResourceScopesMedia), "The data wrapper for the response")
		a.Required("data")
	})
	a.View("default", func() {
		a.Attribute("data")
	})
})

var ResourceScopesMedia = a.MediaType("application/vnd.resource_scopes+json", func() {
	a.Description("Resource scopes payload")
	a.Attributes(func() {
		a.Attribute("id", d.String, "Name of the scope")
		a.Attribute("type", d.String, "Type of resource")
		a.Required("id", "type")
	})
	a.View("default", func() {
		a.Attribute("id")
		a.Attribute("type")
	})

})

var RegisterResourceMedia = a.MediaType("application/vnd.register_resource+json", func() {
	a.Description("Payload for registering a resource")
	a.Attributes(func() {
		a.Attribute("type", d.String, "The type of resource")
		a.Attribute("parent_resource_id", d.String, "The parent resource (of the same type) to which this resource belongs")
		a.Attribute("resource_id", d.String, "The identifier for this resource. If left blank, one will be generated")
		a.Required("type")
	})
	a.View("default", func() {
		a.Attribute("type")
		a.Attribute("parent_resource_id")
		a.Attribute("resource_id")
	})
})

var RegisterResourceResponseMedia = a.MediaType("application/vnd.register_resource_response+json", func() {
	a.Description("Response returned when a resource is registered")
	a.Attributes(func() {
		a.Attribute("resource_id", d.String, "The identifier for the registered resource")
	})
	a.View("default", func() {
		a.Attribute("resource_id")
	})
})

package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("resource_roles", func() {

	a.BasePath("/resources")
	a.Action("listAssigned", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/:resourceID/roles/assigned"),
		)
		a.Description("List assigned roles by resource")
		a.Response(d.OK, identityRolesMedia)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
	})
	a.Action("listAssignedByRoleName", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/:resourceID/roles/:roleName/assigned"),
		)
		a.Description("List assigned roles for a specific role name, for a specific resource")
		a.Response(d.OK, identityRolesMedia)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
	})
})

// ResourceMedia represents a protected resource
var identityRolesMedia = a.MediaType("application/vnd.identityRoles+json", func() {
	a.Description("Assigned Roles in a Protected Resource")
	a.Attributes(func() {
		// keeping one level of nesting so that it's easier to add metadata in future.
		a.Attribute("data", a.ArrayOf(identityRolesData))
		a.Required("data")
	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

var identityRolesData = a.Type("identityRolesData", func() {
	a.Attribute("role_name", d.String, "The name of the role")
	a.Attribute("assignee_id", d.String, "The ID of the assignee")
	a.Attribute("assignee_type", d.String, "The type of assignee, example: user,group,team")
	a.Attribute("inherited", d.Boolean)
	a.Attribute("inherited_from", d.String, "The ID of the resource from this role was inherited")

	a.Required("role_name", "assignee_id", "assignee_type", "inherited")
})

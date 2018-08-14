package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("roles", func() {
	a.BasePath("/roles")
	a.Action("list", func() {
		a.Security("jwt")
		a.Routing(
			a.GET(""),
		)
		a.Params(func() {
			a.Param("resource_type", d.String, "resource type for which roles are being listed")
		})
		a.Description("List available roles by resource type")
		a.Response(d.OK, rolesMedia)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})
})

var rolesMedia = a.MediaType("application/vnd.roles+json", func() {
	a.Description("Available Roles for a Resource Type")
	a.Attributes(func() {
		// keeping one level of nesting so that it's easier to add metadata in future.
		a.Attribute("data", a.ArrayOf(rolesData))
		a.Required("data")
	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

var rolesData = a.Type("rolesData", func() {
	a.Attribute("role_name", d.String, "The name of the role")
	a.Attribute("resource_type", d.String, "The resource type ")
	a.Attribute("scope", a.ArrayOf(d.String), "The scopes defined for this role")

	a.Required("role_name", "resource_type", "scope")
})

var _ = a.Resource("resource_roles", func() {

	a.BasePath("/resources")
	a.Action("listAssigned", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/:resourceID/roles"),
		)
		a.Description("List assigned roles by resource")
		a.Response(d.OK, identityRolesMedia)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
	})
	a.Action("listAssignedByRoleName", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/:resourceID/roles/:roleName"),
		)
		a.Description("List assigned roles for a specific role name, for a specific resource")
		a.Response(d.OK, identityRolesMedia)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
	})
	a.Action("assignRole", func() {
		a.Security("jwt")
		a.Routing(
			a.PUT("/:resourceID/roles"),
		)
		a.Payload(assignRoleArray) // should refactor this variable's name in collaborators design definition too.
		a.Description("Assigns roles to one or more identities, for a specific resource")
		a.Response(d.NoContent)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Conflict, JSONAPIErrors)
	})
	a.Action("hasScope", func() {
		a.Routing(
			a.GET("/:resourceId/scopes/:scopeName"),
		)
		a.Params(func() {
			a.Param("resourceId", d.String, "The identifier of the resource to check for a user scope")
			a.Param("scopeName", d.String, "The name of the scope to check for the user")
		})
		a.Description("Checks if the user has the given scope on the requested resource")
		a.Response(d.OK, identityResourceScope)
		a.Response(d.Unauthorized, JSONAPIErrors)
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

var assignRoleArray = a.MediaType("application/vnd.assign-role-array+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("AssignRoleArray")
	a.Description("Role Assignment Array")
	a.Attributes(func() {
		a.Attribute("data", a.ArrayOf(assignRoleData))
		a.Required("data")
	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

var assignRoleData = a.Type("AssignRoleData", func() {
	a.Attribute("role", d.String, "name of the role to assign")
	a.Attribute("ids", a.ArrayOf(d.String), "identity ids to assign role to")
	a.Required("role", "ids")
})

// identityResourceScopes represents a response to a permission/scope check for a user on a given resource
var identityResourceScope = a.MediaType("application/vnd.resource.scopes+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("IdentityResourceScope")
	a.Description("HasScopes for a user on a resource")
	a.Attributes(func() {
		a.Attribute("data", identityResourceScopeData)
		a.Required("data")
	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

// identityResourceScopeData
var identityResourceScopeData = a.Type("identityResourceScopeData", func() {
	a.Attribute("scopeName", d.String, "the name of the scope that was checked")
	a.Attribute("hasScope", d.Boolean, "'true' if the user has the given scope, 'false' otherwise")
	a.Required("scopeName", "hasScope")
})

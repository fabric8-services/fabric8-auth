package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

// spaceResource represents a Keycloak Resource associated with the Space
var spaceResource = a.MediaType("application/vnd.spaceresource+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("SpaceResource")
	a.Description("Space Resource")
	a.Attributes(func() {
		a.Attribute("data", spaceResourceData)
		a.Required("data")
	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

// spaceResourceData represents a Keycloak Resource Data associated with the Space
var spaceResourceData = a.Type("SpaceResourceData", func() {
	a.Attribute("resourceID", d.String, "Keycloak Resource ID associated with this Space")
	a.Attribute("permissionID", d.String, "Keycloak Permission ID associated with this Space")
	a.Attribute("policyID", d.String, "Keycloak Policy ID associated with this Space")
	a.Required("resourceID", "permissionID", "policyID")
})

var space = a.Type("Space", func() {
	a.Attribute("id", d.UUID, "ID of the space", func() {
		a.Example("40bbdd3d-8b5d-4fd6-ac90-7236b669af04")
	})
})

var _ = a.Resource("space", func() {
	a.BasePath("/spaces")

	a.Action("create", func() {
		a.Security("jwt")
		a.Routing(
			a.POST("/:spaceID"),
		)
		a.Description("Create a space resource for the giving space")
		a.Params(func() {
			a.Param("spaceID", d.UUID, "ID of the space")
		})
		a.Response(d.OK, spaceResource)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Conflict, JSONAPIErrors)
	})

	a.Action("delete", func() {
		a.Security("jwt")
		a.Routing(
			a.DELETE("/:spaceID"),
		)
		a.Description("Delete a space resource for the given space ID")
		a.Params(func() {
			a.Param("spaceID", d.UUID, "ID of the space")
		})
		a.Response(d.OK)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
	})

	a.Action("listTeams", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/:spaceID/teams"),
		)
		a.Description("Lists teams for the specified space")
		a.Params(func() {
			a.Param("spaceID", d.String, "ID of the space")
		})
		a.Response(d.OK, teamArray)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
	})
})

var teamArray = a.MediaType("application/vnd.team-array+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("TeamArray")
	a.Description("Team Array")
	a.Attributes(func() {
		a.Attribute("data", a.ArrayOf(teamData))
		a.Required("data")

	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

var teamData = a.Type("TeamData", func() {
	a.Attribute("id", d.String, "unique id for the team")
	a.Attribute("name", d.String, "name of the team")
	a.Required("id", "name")
})

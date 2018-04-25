package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("team", func() {

	a.BasePath("/teams")

	a.Action("create", func() {
		a.Security("jwt")
		a.Routing(
			a.POST(""),
		)
		a.Description("Create a new team")
		a.Payload(CreateTeamRequestMedia)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Created, CreateTeamResponseMedia)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})

	a.Action("list", func() {
		a.Security("jwt")
		a.Routing(
			a.GET(""),
		)
		a.Description("Lists teams that the user has access to")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.OK, identityTeamArray)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})
})

var CreateTeamRequestMedia = a.MediaType("application/vnd.create_team_request+json", func() {
	a.Description("Request payload required to create a new team")
	a.Attributes(func() {
		a.Attribute("space_id", d.String, "The identifier of the space in which to create the team")
		a.Attribute("name", d.String, "The name of the new team")
	})
	a.View("default", func() {
		a.Attribute("space_id")
		a.Attribute("name")
	})
})

var CreateTeamResponseMedia = a.MediaType("application/vnd.create_team_response+json", func() {
	a.Description("Response returned when creating a new team")
	a.Attributes(func() {
		a.Attribute("team_id", d.String, "The identifier of the new team")
	})
	a.View("default", func() {
		a.Attribute("team_id")
	})
})

var identityTeamArray = a.MediaType("application/vnd.identity-team-array+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("IdentityTeamArray")
	a.Description("Identity Team Array")
	a.Attributes(func() {
		a.Attribute("data", a.ArrayOf(identityTeamData))
		a.Required("data")

	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

var identityTeamData = a.Type("IdentityTeamData", func() {
	a.Attribute("id", d.String, "unique id for the team")
	a.Attribute("name", d.String, "name of the team")
	a.Attribute("space_id", d.String, "unique id of the space the team belongs to")
	a.Attribute("space_name", d.String, "name of the space the team belongs to")
	a.Attribute("member", d.Boolean, "flag indicating whether the user is a member of the team")
	a.Attribute("roles", a.ArrayOf(d.String), "roles assigned to the user for the team")
	a.Required("id", "name", "space_id", "space_name", "member", "roles")
})

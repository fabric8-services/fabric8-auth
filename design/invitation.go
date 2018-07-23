package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("invitation", func() {

	a.BasePath("/invitations")

	a.Action("createInvite", func() {
		a.Security("jwt")
		a.Routing(
			a.POST("/:inviteTo"),
		)
		a.Params(func() {
			a.Param("inviteTo", d.String, "Unique identifier of the organization, team, security group or resource")
		})
		a.Description("Create a new invitation for a user to join an organization, team or security group, or accept a role for a resource")
		a.Payload(CreateInvitationRequestMedia)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Created)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})

	a.Action("acceptInvite", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/accept/:acceptCode"),
		)
		a.Params(func() {
			a.Param("acceptCode", d.String, "Unique acceptance code for a user to accept a previously extended invitation")
		})
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})

	a.Action("rescindInvite", func() {
		a.Security("jwt")
		a.Routing(
			a.DELETE("/:inviteTo"),
		)
		a.Params(func() {
			a.Param("inviteTo", d.String, "Unique identifier for the invitation to the organization, team, security group or resource")
		})
		a.Response(d.OK)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})
})

var CreateInvitationRequestMedia = a.MediaType("application/vnd.create_invitation_request+json", func() {
	a.Description("Request payload required to create new invitations")
	a.Attributes(func() {
		a.Attribute("data", a.ArrayOf(invitee), "An array of users invited to become members or to accept a role")
	})
	a.Required("data")
	a.View("default", func() {
		a.Attribute("data")
	})
})

var invitee = a.Type("Invitee", func() {
	a.Attribute("identity-id", d.String, "unique id for the user identity")
	a.Attribute("member", d.Boolean, "if true invites the user to become a member")
	a.Attribute("roles", a.ArrayOf(d.String), "An array of role names")
})

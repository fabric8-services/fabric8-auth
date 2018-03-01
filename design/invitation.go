package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("invitation", func() {

	a.BasePath("/invitations")

	a.Action("create", func() {
		a.Security("jwt")
		a.Routing(
			a.POST("/:inviteTo"),
		)
		a.Params(func() {
			a.Param("inviteTo", d.String, "Unique identifier of the organization, team or security group")
		})
		a.Description("Create a new invitation for a user to join an organization, team or security group")
		a.Payload(CreateInvitationRequestMedia)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Created)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})

	a.Action("list", func() {
		a.Security("jwt")
		a.Routing(
			a.GET(""),
		)
		a.Description("Lists invitations for an organization, team or group that the user has the invite_user scope for, or lists invitations for the current user")
		a.Response(d.Unauthorized, JSONAPIErrors)
		//a.Response(d.OK, invitationArray)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})
})

var CreateInvitationRequestMedia = a.MediaType("application/vnd.create_invitation_request+json", func() {
	a.Description("Request payload required to create new invitations")
	a.Attributes(func() {
		a.Attribute("members", a.ArrayOf(invitee), "An array of prospective members that will be invited to join")
		a.Attribute("roles", a.ArrayOf(invitedRole), "An array of users invited to accept a role")
	})
	a.Required("members", "roles")
	a.View("default", func() {
		a.Attribute("members")
		a.Attribute("roles")
	})
})

var invitee = a.Type("Invitee", func() {
	a.Attribute("identity-id", d.String, "unique id for the user identity")
	a.Attribute("username", d.String, "username of the user")
	a.Attribute("user-email", d.String, "e-mail address of the user")
})

var invitedRole = a.Type("InvitedRole", func() {
	a.Attribute("identity-id", d.String, "unique id for the user identity")
	a.Attribute("username", d.String, "username of the user")
	a.Attribute("user-email", d.String, "e-mail address of the user")
	a.Attribute("roles", a.ArrayOf(d.String), "An array of role names")
	a.Required("roles")
})

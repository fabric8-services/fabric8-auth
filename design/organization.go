package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("organization", func() {

	a.BasePath("/organization")

	a.Action("create", func() {
		a.Routing(
			a.POST(""),
		)
		a.Description("Create a new organization")
		a.Payload(CreateOrganizationRequestMedia)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Created, CreateOrganizationResponseMedia)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})

	a.Action("list", func() {
		a.Routing(
			a.GET(""),
		)
		a.Description("Lists organizations that the user has access to")
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.OK, organizationArray)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
	})
})

var CreateOrganizationRequestMedia = a.MediaType("application/vnd.create_organization_request+json", func() {
	a.Description("Request payload required to create a new organization")
	a.Attributes(func() {
		a.Attribute("name", d.String, "The name of the new organization")
	})
	a.View("default", func() {
		a.Attribute("name")
	})
})

var CreateOrganizationResponseMedia = a.MediaType("application/vnd.create_organization_response+json", func() {
	a.Description("Response returned when creating a new organization")
	a.Attributes(func() {
		a.Attribute("organization_id", d.String, "The identifier of the new organization")
	})
	a.View("default", func() {
		a.Attribute("organization_id")
	})
})

var organizationArray = a.MediaType("application/vnd.organization-array+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("OrganizationArray")
	a.Description("Organization Array")
	a.Attributes(func() {
		a.Attribute("organizations", a.ArrayOf(organizationData))
		a.Required("organizations")

	})
	a.View("default", func() {
		a.Attribute("organizations")
		a.Required("organizations")
	})
})

var organizationData = a.Type("OrganizationData", func() {
	a.Attribute("id", d.String, "unique id for the organization")
	a.Attribute("name", d.String, "name of the organization")
	a.Attribute("member", d.Boolean, "flag indicating whether the user is a member of the organization")
	a.Attribute("roles", a.ArrayOf(d.String), "roles assigned to the user for the organization")
	a.Required("id", "name", "member", "roles")
})

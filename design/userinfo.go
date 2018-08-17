package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("userinfo", func() {
	a.BasePath("/userinfo")

	a.Action("show", func() {
		a.Security("jwt")
		a.Routing(
			a.GET(""),
		)
		a.Description("Get the authenticated user - part of the OAuth/OpenID connect authentication flow")
		a.Response(d.OK, userInfo)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})
})

// userInfo represents an userInfo object
var userInfo = a.MediaType("application/vnd.userInfo+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("UserInfo")
	a.Description("User Information")
	a.Attributes(func() {
		a.Attribute("sub", d.String, "subject (identity is subject)")
		a.Attribute("given_name", d.String, "first name, can be achieved from fullName rrom the user table")
		a.Attribute("family_name", d.String, "last name, can be achieved from fullName from the user table")
		a.Attribute("preferred_username", d.String, "username, each identity has a username")
		a.Attribute("email", d.String, "email of the user")
	})
	a.View("default", func() {
		a.Attribute("sub", d.String)
		a.Attribute("given_name", d.String)
		a.Attribute("family_name", d.String)
		a.Attribute("preferred_username", d.String)
		a.Attribute("email", d.String)
		a.Required("sub", "given_name", "family_name", "preferred_username", "email")
	})
})

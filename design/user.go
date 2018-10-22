package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("user", func() {
	a.BasePath("/user")

	a.Action("show", func() {
		a.Security("jwt")
		a.Routing(
			a.GET(""),
		)
		a.Description("Get the authenticated user in JSON-API format")
		a.UseTrait("conditional")
		a.Response(d.OK, showUser)
		a.Response(d.NotModified)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})

	a.Action("listResources", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/resources"),
		)
		a.Params(func() {
			// requirement and value will be handled by the controller method,
			// in order to be able to return a proper JSON-API response to the client in case
			// of a bad request
			a.Param("type", d.String, "the type of resource to list")
			a.Required("type")
		})
		a.Description("List resources of a given type with a role for the current user")
		a.Response(d.OK, showUserResources)
		a.Response(d.NotModified)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})
})

// showUser represents an identified user object to show
var showUser = a.MediaType("application/vnd.user+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("User")
	a.Description("User Identity")
	a.Attributes(func() {
		a.Attribute("data", userData)
		a.Required("data")

	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

// userArray represents an array of user objects
// Deprecated. Use userList instead
var userArray = a.MediaType("application/vnd.user-array+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("UserArray")
	a.Description("User Array")
	a.Attributes(func() {
		a.Attribute("data", a.ArrayOf(userData))
		a.Required("data")

	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

var userListMeta = a.Type("UserListMeta", func() {
	a.Attribute("totalCount", d.Integer)
	a.Required("totalCount")
})

var userList = JSONList(
	"User", "Holds the paginated response to a user list request",
	userData,
	pagingLinks,
	userListMeta)

// userData represents an identified user object
var userData = a.Type("UserData", func() {
	a.Attribute("id", d.String, "unique id for the user")
	a.Attribute("type", d.String, "type of the user")
	a.Attribute("attributes", userDataAttributes, "Attributes of the user")
	a.Attribute("links", genericLinks)
	a.Required("type", "attributes")
})

// userDataAttributes represents an identified user object attributes
var userDataAttributes = a.Type("UserDataAttributes", func() {
	a.Attribute("userID", d.String, "The id of the corresponding User")
	a.Attribute("identityID", d.String, "The id of the corresponding Identity")
	a.Attribute("created-at", d.DateTime, "The date of creation of the user")
	a.Attribute("updated-at", d.DateTime, "The date of update of the user")
	a.Attribute("fullName", d.String, "The user's full name")
	a.Attribute("imageURL", d.String, "The avatar image for the user")
	a.Attribute("username", d.String, "The username")
	a.Attribute("registrationCompleted", d.Boolean, "Whether the registration has been completed")
	a.Attribute("email", d.String, "The email")
	a.Attribute("emailVerified", d.Boolean, "Whether the email is a verified one")
	a.Attribute("emailPrivate", d.Boolean, "Whether the email address would be private.")
	a.Attribute("bio", d.String, "The bio")
	a.Attribute("url", d.String, "The url")
	a.Attribute("company", d.String, "The company")
	a.Attribute("providerType", d.String, "The IDP provided this identity")
	a.Attribute("cluster", d.String, "The OpenShift API URL of the cluster where the user is provisioned to")
	a.Attribute("featureLevel", d.String, "The level of features that the user wants to use (for unreleased features)")
	a.Attribute("deprovisioned", d.Boolean, "Whether the user has been deprovisioned")
	a.Attribute("contextInformation", a.HashOf(d.String, d.Any), "User context information of any type as a json", func() {
		a.Example(map[string]interface{}{"last_visited_url": "https://a.openshift.io", "space": "3d6dab8d-f204-42e8-ab29-cdb1c93130ad"})
	})
})

// showUserResources a list of resources in which the user has a role
var showUserResources = JSONList(
	"UserResources", "Holds the paginated response to a user spaces request",
	userResourceData,
	pagingLinks,
	userListMeta)

// userResourceData represents a resource for which a user has a role
var userResourceData = a.Type("UserResourceData", func() {
	a.Attribute("id", d.String, "id of the resource that in which the user has a role")
	a.Attribute("type", d.String, "type of the resource")
	a.Attribute("links", genericLinks)
	a.Required("id", "type")
})

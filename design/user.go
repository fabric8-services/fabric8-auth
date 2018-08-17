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
		})
		a.Description("List resources of a given type with a role for the current user")
		// a.UseTrait("conditional")
		a.Response(d.OK, showUserResources)
		a.Response(d.NotModified)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})
})

var _ = a.Resource("users", func() {
	a.BasePath("/users")

	a.Action("verifyEmail", func() {
		a.Routing(
			a.GET("/verifyemail"),
		)
		a.Params(func() {
			a.Param("code", d.String, "code")
			a.Required("code")
		})
		a.Description("Verify if the new email updated by the user is a valid email")
		a.Response(d.TemporaryRedirect)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})

	a.Action("sendEmailVerificationCode", func() {
		a.Security("jwt")
		a.Routing(
			a.POST("/verificationcode"),
		)
		a.Description("Send a verification code to the user's email address")
		a.Response(d.NoContent)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})

	a.Action("show", func() {
		a.Routing(
			a.GET("/:id"),
		)
		a.Description("Retrieve user for the given ID.")
		a.Params(func() {
			a.Param("id", d.String, "Identity ID")
		})
		a.UseTrait("conditional")
		a.Response(d.OK, showUser)
		a.Response(d.NotModified)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})

	a.Action("create", func() {
		a.Security("jwt")
		a.Routing(
			a.POST(""),
		)
		a.Description("create a user using a service account")
		a.Payload(createUser)
		a.Response(d.OK, func() {
			a.Media(showUser)
		})
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.Conflict, JSONAPIErrors)
	})

	a.Action("update", func() {
		a.Security("jwt")
		a.Routing(
			a.PATCH(""),
		)
		a.Description("update the authenticated user")
		a.Payload(updateUser)
		a.Response(d.OK, func() {
			a.Media(showUser)
		})
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
		a.Response(d.Conflict, JSONAPIErrors)
	})

	a.Action("list", func() {
		a.Routing(
			a.GET(""),
		)
		a.Description("List all users.")
		a.Params(func() {
			// This is not filtering - mutliple params do not work as "AND".
			a.Param("filter[username]", d.String, "username to search users")
			a.Param("filter[email]", d.String, "email to search users")
		})
		a.UseTrait("conditional")
		a.Response(d.OK, userArray)
		a.Response(d.NotModified)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})
})

var _ = a.Resource("namedusers", func() {
	a.BasePath("/namedusers")
	a.Action("deprovision", func() {
		a.Security("jwt")
		a.Routing(
			a.PATCH("/:username/deprovision"),
		)
		a.Description("deprovision the user")
		a.Params(func() {
			a.Param("username", d.String, "Username")
		})
		a.Response(d.OK, func() {
			a.Media(showUser)
		})
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.Forbidden, JSONAPIErrors)
	})
})

// createUser represents an identified user object to create
var createUser = a.MediaType("application/vnd.createuser+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("CreateUser")
	a.Description("User Create")
	a.Attributes(func() {
		a.Attribute("data", createUserData)
		a.Required("data")
	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

// createUserData represents the data of an identified user object to create
var createUserData = a.Type("CreateUserData", func() {
	a.Attribute("type", d.String, "type of the user identity")
	a.Attribute("attributes", createUserDataAttributes, "Attributes of the user identity")
	a.Attribute("links", genericLinks)
	a.Required("type", "attributes")
})

// updateUser represents an identified user object to update
var updateUser = a.MediaType("application/vnd.updateuser+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("UpdateUser")
	a.Description("User Update")
	a.Attributes(func() {
		a.Attribute("data", updateUserData)
		a.Required("data")

	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

// updateUserData represents the data of an identified user object to update
var updateUserData = a.Type("UpdateUserData", func() {
	a.Attribute("type", d.String, "type of the user identity")
	a.Attribute("attributes", updateUserDataAttributes, "Attributes of the user identity")
	a.Attribute("links", genericLinks)
	a.Required("type", "attributes")
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
	a.Attribute("attributes", userResourceDataAttributes, "Info about the role and scopes that the user has in the resource")
	a.Attribute("links", genericLinks)
	a.Required("id", "type", "attributes")
})

// userResourceDataAttributes contains info about the role and scopes that the user has in the resource
var userResourceDataAttributes = a.Type("UserResourceDataAttributes", func() {
	a.Attribute("role", d.String, "The role of the user in the corresponding resource")
	a.Attribute("scopes", a.ArrayOf(d.String), "The scopes associated with the role of the user in the corresponding resource")
	a.Required("role", "scopes")
})

// updateUserDataAttributes represents an identified user object attributes used for updating a user.
var updateUserDataAttributes = a.Type("UpdateIdentityDataAttributes", func() {
	a.Attribute("fullName", d.String, "The users full name")
	a.Attribute("imageURL", d.String, "The avatar image for the user")
	a.Attribute("username", d.String, "The username")
	a.Attribute("email", d.String, "The email")
	a.Attribute("bio", d.String, "The bio")
	a.Attribute("url", d.String, "The url")
	a.Attribute("emailPrivate", d.Boolean, "Whether the email address would be private.")
	a.Attribute("company", d.String, "The company")
	a.Attribute("featureLevel", d.String, "The level of features that the user wants to use (for unreleased features)")
	a.Attribute("registrationCompleted", d.Boolean, "Complete the registration to proceed. This can only be set to true")
	a.Attribute("contextInformation", a.HashOf(d.String, d.Any), "User context information of any type as a json", func() {
		a.Example(map[string]interface{}{"last_visited_url": "https://a.openshift.io", "space": "3d6dab8d-f204-42e8-ab29-cdb1c93130ad"})
	})
	a.Attribute("deprovisioned", d.Boolean, "Whether the identity has been deprovisioned")
})

// identityData represents an identified identity object
var identityData = a.Type("IdentityData", func() {
	a.Attribute("id", d.String, "unique id for the user identity")
	a.Attribute("type", d.String, "type of the user identity")
	a.Attribute("attributes", identityDataAttributes, "Attributes of the user identity")
	a.Attribute("links", genericLinks)
	a.Required("type", "attributes")
})

// identityDataAttributes represents an identified identity object attributes
var identityDataAttributes = a.Type("IdentityDataAttributes", func() {
	a.Attribute("created-at", d.DateTime, "The date of creation of the user")
	a.Attribute("updated-at", d.DateTime, "The date of update of the user")
	a.Attribute("username", d.String, "The username")
	a.Attribute("providerType", d.String, "The IDP provided this identity")
})

var createUserDataAttributes = a.Type("CreateIdentityDataAttributes", func() {
	a.Attribute("fullName", d.String, "The user's full name")
	a.Attribute("imageURL", d.String, "The avatar image for the user")
	a.Attribute("username", d.String, "The username")
	a.Attribute("registrationCompleted", d.Boolean, "Whether the registration has been completed")
	a.Attribute("email", d.String, "The email")
	a.Attribute("approved", d.Boolean, "Whether the user is approved for using an OpenShift cluster. 'True' is used by default")
	a.Attribute("emailVerified", d.Boolean, "Whether email is verified")
	a.Attribute("enabled", d.Boolean, "Whether the user is enabled")
	a.Attribute("rhd_username", d.String, "The associated Red Hat Developers account. If not set then username is used as the RHD username")
	a.Attribute("rhd_user_id", d.String, "The Red Hat Developers User ID of the user")
	a.Attribute("bio", d.String, "The bio")
	a.Attribute("url", d.String, "The url")
	a.Attribute("company", d.String, "The company")
	a.Attribute("cluster", d.String, "The OpenShift API URL of the cluster where the user is provisioned to")
	a.Attribute("providerType", d.String, "The IDP provided this identity")
	a.Attribute("featureLevel", d.String, "The level of features that the user wants to use (for unreleased features)")
	a.Attribute("contextInformation", a.HashOf(d.String, d.Any), "User context information of any type as a json", func() {
		a.Example(map[string]interface{}{"last_visited_url": "https://a.openshift.io", "space": "3d6dab8d-f204-42e8-ab29-cdb1c93130ad"})
	})
	// Based on the request from online-registration app.
	a.Required("username", "email", "cluster", "rhd_user_id")
})

package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

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

	a.Action("listTokens", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/:id/tokens"),
		)
		a.Params(func() {
			a.Param("id", d.String, "the ID value of the user's identity")
			a.Required("identityID")
		})
		a.Description("List all tokens for a specified user")
		a.Response(d.OK, userTokenArray)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})

	a.Action("RevokeAllTokens", func() {
		a.Security("jwt")
		a.Routing(
			a.DELETE("/:id/tokens"),
		)
		a.Params(func() {
			a.Param("id", d.String, "Identifier of the identity for which all tokens will be revoked")
			a.Required("identityID")
		})
		a.Description("Revokes all tokens for a specified identity id")
		a.Response(d.OK)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
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
	a.Attribute("deprovisioned", d.Boolean, "Whether the identity has been deprovisioned (DEPRECATED: use 'banned' instead)")
	a.Attribute("banned", d.Boolean, "Whether the identity has been banned")
})

var userTokenArray = a.MediaType("application/vnd.user-token-array+json", func() {
	a.UseTrait("jsonapi-media-type")
	a.TypeName("UserTokenArray")
	a.Description("User Token Array")
	a.Attributes(func() {
		a.Attribute("data", a.ArrayOf(userTokenData))
		a.Required("data")

	})
	a.View("default", func() {
		a.Attribute("data")
		a.Required("data")
	})
})

var userTokenData = a.Type("UserTokenData", func() {
	a.Attribute("token_id", d.String, "unique token identifier")
	a.Attribute("status", d.Integer, "token status")
	a.Attribute("token_type", d.String, "token type")
	a.Attribute("expiry_time", d.DateTime, "token expiry time")
	a.Attribute("permissions", a.ArrayOf(tokenPrivilegeData))
	a.Required("token_id", "status", "token_type", "expiry_time")
})

var tokenPrivilegeData = a.Type("TokenPrivilegeData", func() {
	a.Attribute("resource_id", d.String, "resource identifier")
	a.Attribute("scopes", d.String, "scopes granted for resource")
	a.Attribute("stale", d.Boolean, "flag indicating whether these privileges are stale")
	a.Required("resource_id", "scopes", "stale")
})

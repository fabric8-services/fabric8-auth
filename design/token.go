package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var _ = a.Resource("token", func() {

	a.BasePath("/token")

	a.Action("keys", func() {
		a.Routing(
			a.GET("keys"),
		)
		a.Params(func() {
			a.Param("format", d.String, func() {
				a.Enum("pem", "jwk")
				a.Description("Key format. If set to \"jwk\" (used by default) then JSON Web Key format will be used. If \"pem\" then a PEM-like format (PEM without header and footer) will be used.")
			})
		})
		a.Description("Returns public keys which should be used to verify tokens")
		a.Response(d.OK, func() {
			a.Media(PublicKeys)
		})
	})

	a.Action("generate", func() {
		a.Routing(
			a.GET("generate"),
		)
		a.Description("Generate a set of Tokens for different Auth levels. NOT FOR PRODUCTION. Only available if server is running in dev mode")
		a.Response(d.OK, func() {
			a.Media(a.CollectionOf(AuthToken))
		})
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})

	a.Action("refresh", func() {
		a.Routing(
			a.POST("refresh"),
		)
		a.Payload(refreshToken)
		a.Description("Refresh access token")
		a.Response(d.OK, func() {
			a.Media(AuthToken)
		})
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
	})
})

// PublicKeys represents an public keys payload
var PublicKeys = a.MediaType("application/vnd.publickeys+json", func() {
	a.TypeName("PublicKeys")
	a.Description("Public Keys")
	a.Attributes(func() {
		a.Attribute("keys", a.ArrayOf(d.Any))
		a.Required("keys")
	})
	a.View("default", func() {
		a.Attribute("keys")
	})
})

var refreshToken = a.Type("RefreshToken", func() {
	a.Attribute("refresh_token", d.String, "Refresh token")
})

// AuthToken represents an authentication JWT Token
var AuthToken = a.MediaType("application/vnd.authtoken+json", func() {
	a.TypeName("AuthToken")
	a.Description("JWT Token")
	a.Attributes(func() {
		a.Attribute("token", tokenData)
		a.Required("token")
	})
	a.View("default", func() {
		a.Attribute("token")
	})
})

var tokenData = a.Type("TokenData", func() {
	a.Attribute("access_token", d.String, "Access token")
	a.Attribute("expires_in", d.Any, "Access token expires in seconds")
	a.Attribute("refresh_expires_in", d.Any, "Refresh token expires in seconds")
	a.Attribute("refresh_token", d.String, "Refresh token")
	a.Attribute("token_type", d.String, "Token type")
	a.Attribute("not-before-policy", d.Any, "Token is not valid if issued before this date")
	a.Required("expires_in")
	a.Required("refresh_expires_in")
	a.Required("not-before-policy")
})

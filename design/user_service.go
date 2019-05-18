package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

var userService = a.Type("UserService", func() {
	a.Description(`JSONAPI for the teant object. See also http://jsonapi.org/format/#document-resource-object`)
	a.Attribute("type", d.String, func() {
		a.Enum("userservices")
	})
	a.Attribute("id", d.UUID, "ID of tenant", func() {
		a.Example("40bbdd3d-8b5d-4fd6-ac90-7236b669af04")
	})
	a.Attribute("attributes", userServiceAttributes)
	a.Attribute("links", genericLinks)
	a.Required("type", "attributes")
})

var userServiceAttributes = a.Type("UserServiceAttributes", func() {
	a.Description(`JSONAPI store for all the "attributes" of a UserService. See also see http://jsonapi.org/format/#document-resource-object-attributes`)
	a.Attribute("created-at", d.DateTime, "When the tenant was created", func() {
		a.Example("2016-11-29T23:18:14Z")
	})
	a.Attribute("namespaces", a.ArrayOf(namespaceAttributes), "The tenant namespaces")
})

var namespaceAttributes = a.Type("NamespaceAttributes", func() {
	a.Description(`JSONAPI store for all the "attributes" of a Tenant namespace. See also see http://jsonapi.org/format/#document-resource-object-attributes`)
	a.Attribute("name", d.String, "The namespace name", func() {
		a.Example("Name for the tenant namespace")
	})
	a.Attribute("created-at", d.DateTime, "When the tenant was created", func() {
		a.Example("2016-11-29T23:18:14Z")
	})
	a.Attribute("updated-at", d.DateTime, "When the tenant was updated", func() {
		a.Example("2016-11-29T23:18:14Z")
	})
	a.Attribute("version", d.String, "The namespaces version")
	a.Attribute("state", d.String, "The namespaces state")
	a.Attribute("cluster-url", d.String, "The cluster url")
	a.Attribute("cluster-console-url", d.String, "The cluster console url")
	a.Attribute("cluster-metrics-url", d.String, "The cluster metrics url")
	a.Attribute("cluster-logging-url", d.String, "The cluster logging url")
	a.Attribute("cluster-app-domain", d.String, "The cluster app domain")
	a.Attribute("cluster-capacity-exhausted", d.Boolean, "Whether cluster hosting this namespace exhausted it's capacity")
	a.Attribute("type", d.String, "The tenant namespaces", func() {
		a.Enum("che", "jenkins", "stage", "test", "run")
	})
})

var userServiceSingle = JSONSingle(
	"userService", "Holds a single Tenant",
	userService,
	nil)

var _ = a.Resource("UserService", func() {
	a.Parent("user")
	a.BasePath("/services")

	a.Action("show", func() {
		a.Security("jwt")
		a.Routing(
			a.GET(""),
		)
		a.Description("Get the authenticated user tenant services")
		a.Response(d.OK, userServiceSingle)
		a.Response(d.BadRequest, JSONAPIErrors)
		a.Response(d.NotFound, JSONAPIErrors)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
	})
})

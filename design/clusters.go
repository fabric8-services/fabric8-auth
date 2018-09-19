package design

import (
	d "github.com/goadesign/goa/design"
	a "github.com/goadesign/goa/design/apidsl"
)

// clusterList represents an array of cluster objects
var clusterList = JSONList(
	"Cluster",
	"Holds the response to a cluster list request",
	clusterData,
	nil,
	nil)

var clusterData = a.Type("ClusterData", func() {
	a.Attribute("name", d.String, "Cluster name")
	a.Attribute("api-url", d.String, "API URL")
	a.Attribute("console-url", d.String, "Web console URL")
	a.Attribute("metrics-url", d.String, "Metrics URL")
	a.Attribute("logging-url", d.String, "Logging URL")
	a.Attribute("app-dns", d.String, "User application domain name in the cluster")
	a.Attribute("capacity-exhausted", d.Boolean, "Cluster is full if set to 'true'")
	a.Required("name", "console-url", "metrics-url", "api-url", "logging-url", "app-dns", "capacity-exhausted")
})

var _ = a.Resource("clusters", func() {
	a.BasePath("/clusters")

	a.Action("show", func() {
		a.Security("jwt")
		a.Routing(
			a.GET("/"),
		)
		a.Description("Get clusters configuration")
		a.Response(d.OK, clusterList)
		a.Response(d.InternalServerError, JSONAPIErrors)
		a.Response(d.Unauthorized, JSONAPIErrors)
		a.Response(d.BadGateway, JSONAPIErrors)
	})
})

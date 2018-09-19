package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/fabric8-services/fabric8-common/http/proxy"

	"github.com/goadesign/goa"
)

type clusterConfiguration interface {
	GetClusterServiceURL() string
}

// ClustersController implements the clusters resource.
type ClustersController struct {
	*goa.Controller
	config clusterConfiguration
}

// NewClustersController creates a clusters controller.
func NewClustersController(service *goa.Service, config clusterConfiguration) *ClustersController {
	return &ClustersController{
		Controller: service.NewController("ClustersController"),
		config:     config,
	}
}

// Show runs the list of available OSO clusters.
func (c *ClustersController) Show(ctx *app.ShowClustersContext) error {
	err := proxy.RouteHTTP(ctx, c.config.GetClusterServiceURL())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to proxy to cluster service")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return nil
}

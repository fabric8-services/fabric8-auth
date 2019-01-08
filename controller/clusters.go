package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/fabric8-services/fabric8-common/httpsupport"

	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/goadesign/goa"
)

type clusterConfiguration interface {
	GetClusterServiceURL() string
}

// ClustersController implements the clusters resource.
type ClustersController struct {
	*goa.Controller
	config clusterConfiguration
	app    application.Application
}

// NewClustersController creates a clusters controller.
func NewClustersController(service *goa.Service, app application.Application, config clusterConfiguration) *ClustersController {
	return &ClustersController{
		Controller: service.NewController("ClustersController"),
		app:        app,
		config:     config,
	}
}

// Show runs the list of available OSO clusters.
func (c *ClustersController) Show(ctx *app.ShowClustersContext) error {
	err := httpsupport.RouteHTTP(ctx, c.config.GetClusterServiceURL())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to proxy to cluster service")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return nil
}

func (c *ClustersController) LinkExistingIdentitiesToCluster(ctx *app.LinkExistingIdentitiesToClusterClustersContext) error {
	if !token.IsSpecificServiceAccount(ctx, token.Migration) {
		log.Error(ctx, nil, "The service account is not authorized to link identities to cluster")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("account not authorized to link identities to cluster"))
	}

	if err := c.app.ClusterService().LinkExistingIdentitiesToCluster(ctx); err != nil {
		log.Error(ctx, map[string]interface{}{
			"error": err,
		}, "error while linking existing identities to  it's cluster url")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	return ctx.Accepted()
}

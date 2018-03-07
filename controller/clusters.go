package controller

import (
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
)

type clusterConfiguration interface {
	GetOSOClusters() map[string]configuration.OSOCluster
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
	if !token.IsSpecificServiceAccount(ctx, token.OsoProxy, token.Tenant, token.JenkinsIdler, token.JenkinsProxy) {
		log.Error(ctx, nil, "unauthorized access to cluster info")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("unauthorized access to cluster info"))
	}
	var data []*app.ClusterData
	for _, clusterConfig := range c.config.GetOSOClusters() {
		cluster := &app.ClusterData{
			Name:       clusterConfig.Name,
			APIURL:     rest.AddTrailingSlashToURL(clusterConfig.APIURL),
			ConsoleURL: rest.AddTrailingSlashToURL(clusterConfig.ConsoleURL),
			MetricsURL: rest.AddTrailingSlashToURL(clusterConfig.MetricsURL),
			LoggingURL: rest.AddTrailingSlashToURL(clusterConfig.LoggingURL),
			AppDNS:     clusterConfig.AppDNS,
		}
		data = append(data, cluster)
	}
	clusters := app.ClusterList{
		Data: data,
	}
	return ctx.OK(&clusters)
}

package service

import (
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/rest"
)

type clusterService struct {
	base.BaseService
}

// NewClusterService creates a new cluster service
func NewClusterService(context servicecontext.ServiceContext) service.ClusterService {
	return &clusterService{
		BaseService: base.NewBaseService(context),
	}
}

// Clusters returns cached map of OpenShift clusters
func (s *clusterService) Clusters() []cluster.Cluster {
	clusterCache.refreshLock.RLock()
	defer clusterCache.refreshLock.RUnlock()
	clusters := make([]cluster.Cluster, len(clusterCache.clusters))
	for _, cls := range clusterCache.clusters {
		clusters = append(clusters, *cls)
	}
	return clusters
}

// ClusterByURL returns the cached cluster for the given cluster API URL
func (s *clusterService) ClusterByURL(url string) *cluster.Cluster {
	clusterCache.refreshLock.RLock()
	defer clusterCache.refreshLock.RUnlock()
	return clusterCache.clusters[rest.AddTrailingSlashToURL(url)]
}

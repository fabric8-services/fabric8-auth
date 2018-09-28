package service

import (
	"strings"

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
	if clusterCache == nil {
		return []cluster.Cluster{}
	}
	clusterCache.refreshLock.RLock()
	defer clusterCache.refreshLock.RUnlock()

	return Clusters(clusterCache.clusters)
}

// ClusterByURL returns the cached cluster for the given cluster API URL
func (s *clusterService) ClusterByURL(url string) *cluster.Cluster {
	if clusterCache == nil {
		return nil
	}
	clusterCache.refreshLock.RLock()
	defer clusterCache.refreshLock.RUnlock()

	return ClusterByURL(clusterCache.clusters, url)
}

func Clusters(clusters map[string]*cluster.Cluster) []cluster.Cluster {
	var cs []cluster.Cluster
	for _, cls := range clusters {
		cs = append(cs, *cls)
	}
	return cs
}

func ClusterByURL(clusters map[string]*cluster.Cluster, url string) *cluster.Cluster {
	for apiURL, cluster := range clusters {
		if strings.HasPrefix(rest.AddTrailingSlashToURL(url), apiURL) {
			return cluster
		}
	}

	return nil
}

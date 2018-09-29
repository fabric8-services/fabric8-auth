package service

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicectx "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/rest"
)

// We need only one global instance of cluster cache
var clusterCache *cache
var started uint32
var startLock = sync.Mutex{}

type clusterService struct {
	base.BaseService
	config clusterConfig
}

// NewClusterService creates a new cluster service
func NewClusterService(context servicectx.ServiceContext, config clusterConfig) service.ClusterService {
	return &clusterService{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
}

// Clusters returns cached map of OpenShift clusters
func (s *clusterService) Clusters(ctx context.Context, options ...rest.HTTPClientOption) ([]cluster.Cluster, error) {
	err := Start(ctx, s.config, options...)
	if err != nil {
		return nil, err
	}
	clusterCache.RLock()
	defer clusterCache.RUnlock()

	return Clusters(clusterCache.clusters), nil
}

// ClusterByURL returns the cached cluster for the given cluster API URL
func (s *clusterService) ClusterByURL(ctx context.Context, url string, options ...rest.HTTPClientOption) (*cluster.Cluster, error) {
	err := Start(ctx, s.config, options...)
	if err != nil {
		return nil, err
	}
	clusterCache.RLock()
	defer clusterCache.RUnlock()

	return ClusterByURL(clusterCache.clusters, url), nil
}

// Start initializes the default Cluster cache if it's not initialized already
// Cache initialization loads the list of clusters from the cluster management service and starts regular cache refresher
func Start(ctx context.Context, config clusterConfig, options ...rest.HTTPClientOption) error {
	if atomic.LoadUint32(&started) == 0 {
		// Has not started yet.
		startLock.Lock()
		defer startLock.Unlock()
		if started == 0 {
			clusterCache = newCache(config, options...)
			err := clusterCache.start(ctx)
			if err == nil {
				// Success
				atomic.StoreUint32(&started, 1)
			} else {
				clusterCache = nil
			}
			return err
		}
	}
	return nil
}

// Clusters converts the given cluster map to an array slice
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

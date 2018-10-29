package service

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicectx "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/rest"
)

type clusterServiceConfig interface {
	manager.TokenManagerConfiguration
	GetClusterServiceURL() string
	GetClusterCacheRefreshInterval() time.Duration
}

// We need only one global instance of cluster cache
var clusterCache cluster.ClusterCache
var started uint32
var startLock = sync.Mutex{}

type clusterService struct {
	base.BaseService
	config clusterServiceConfig
}

// NewClusterService creates a new cluster service
func NewClusterService(context *servicectx.ServiceContext, config clusterServiceConfig) service.ClusterService {
	return &clusterService{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
}

// Clusters returns cached map of OpenShift clusters
func (s *clusterService) Clusters(ctx context.Context, options ...rest.HTTPClientOption) ([]cluster.Cluster, error) {
	err := Start(ctx, s.Factories().ClusterCacheFactory(), s.config, options...)
	if err != nil {
		return nil, err
	}
	clusterCache.RLock()
	defer clusterCache.RUnlock()

	return Clusters(clusterCache.Clusters()), nil
}

// ClusterByURL returns the cached cluster for the given cluster API URL
func (s *clusterService) ClusterByURL(ctx context.Context, url string, options ...rest.HTTPClientOption) (*cluster.Cluster, error) {
	err := Start(ctx, s.Factories().ClusterCacheFactory(), s.config, options...)
	if err != nil {
		return nil, err
	}
	clusterCache.RLock()
	defer clusterCache.RUnlock()

	return ClusterByURL(clusterCache.Clusters(), url), nil
}

func (s *clusterService) Status(ctx context.Context) error {
	return Start(ctx, s.Factories().ClusterCacheFactory(), s.config)
}

// Start initializes the default Cluster cache if it's not initialized already
// Cache initialization loads the list of clusters from the cluster management service and starts regular cache refresher
func Start(ctx context.Context, factory service.ClusterCacheFactory, config clusterServiceConfig, options ...rest.HTTPClientOption) error {
	if atomic.LoadUint32(&started) == 0 {
		// Has not started yet.
		startLock.Lock()
		defer startLock.Unlock()
		if started == 0 {
			clusterCache = factory.NewClusterCache(ctx, options...)
			err := clusterCache.Start(ctx)
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
func Clusters(clusters map[string]cluster.Cluster) []cluster.Cluster {
	cs := make([]cluster.Cluster, 0, len(clusters))
	for _, cls := range clusters {
		cs = append(cs, cls)
	}
	return cs
}

func ClusterByURL(clusters map[string]cluster.Cluster, url string) *cluster.Cluster {
	for apiURL, cluster := range clusters {
		if strings.HasPrefix(rest.AddTrailingSlashToURL(url), apiURL) {
			return &cluster
		}
	}

	return nil
}

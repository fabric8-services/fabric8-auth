package test

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/application/factory/wrapper"
	svc "github.com/fabric8-services/fabric8-auth/application/service"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/configuration"

	"github.com/fabric8-services/fabric8-auth/cluster"
	clusterservice "github.com/fabric8-services/fabric8-auth/cluster/service"
	"github.com/fabric8-services/fabric8-auth/rest"
	testservice "github.com/fabric8-services/fabric8-auth/test/generated/application/service"

	"github.com/gojuno/minimock"
	"github.com/satori/go.uuid"
)

var clusters = map[string]cluster.Cluster{
	"https://api.starter-us-east-2.openshift.com/":  newCluster("https://api.starter-us-east-2.openshift.com/"),
	"https://api.starter-us-east-2a.openshift.com/": newCluster("https://api.starter-us-east-2a.openshift.com/"),
}

func NewClusterServiceMock(t minimock.Tester) *testservice.ClusterServiceMock {
	clusterServiceMock := testservice.NewClusterServiceMock(t)
	clusterServiceMock.ClusterByURLFunc = func(ctx context.Context, url string, options ...rest.HTTPClientOption) (*cluster.Cluster, error) {
		return ClusterByURL(url), nil
	}
	clusterServiceMock.ClustersFunc = func(ctx context.Context, options ...rest.HTTPClientOption) ([]cluster.Cluster, error) {
		return clusterservice.Clusters(clusters), nil
	}
	clusterServiceMock.StatusFunc = func(ctx context.Context, options ...rest.HTTPClientOption) (bool, error) {
		return false, nil
	}
	clusterServiceMock.LinkIdentityToClusterFunc = func(p context.Context, identityID uuid.UUID, clusterURL string, options ...rest.HTTPClientOption) (r error) {
		return nil
	}
	clusterServiceMock.UnlinkIdentityFromClusterFunc = func(p context.Context, identityID uuid.UUID, clusterURL string, options ...rest.HTTPClientOption) (r error) {
		return nil
	}

	return clusterServiceMock
}

func ClusterByURL(url string) *cluster.Cluster {
	return clusterservice.ClusterByURL(clusters, url)
}

func newCluster(apiURL string) cluster.Cluster {
	return cluster.Cluster{
		APIURL:                 apiURL,
		MetricsURL:             uuid.NewV4().String(),
		LoggingURL:             uuid.NewV4().String(),
		ConsoleURL:             uuid.NewV4().String(),
		AppDNS:                 uuid.NewV4().String(),
		AuthClientID:           uuid.NewV4().String(),
		AuthClientSecret:       uuid.NewV4().String(),
		AuthClientDefaultScope: uuid.NewV4().String(),
		TokenProviderID:        uuid.NewV4().String(),
		ServiceAccountUsername: "dsaas",
		ServiceAccountToken:    uuid.NewV4().String(),
		Name:                   uuid.NewV4().String(),
	}
}

//----------------------------------------------------------------------------------------------------------------------
//
// Dummy Cluster Cache
//
//----------------------------------------------------------------------------------------------------------------------

type dummyClusterCacheFactory interface {
	setClusterCache(cache cluster.ClusterCache)
}

type dummyClusterCacheFactoryImpl struct {
	wrapper.BaseFactoryWrapper
	cache cluster.ClusterCache
}

func ActivateDummyClusterCacheFactory(w wrapper.Wrapper, cache cluster.ClusterCache) {
	w.WrapFactory(svc.FACTORY_TYPE_CLUSTER_CACHE,
		func(ctx servicecontext.ServiceContext, config *configuration.ConfigurationData) wrapper.FactoryWrapper {
			baseFactoryWrapper := wrapper.NewBaseFactoryWrapper(ctx, config)
			return &dummyClusterCacheFactoryImpl{
				BaseFactoryWrapper: *baseFactoryWrapper,
			}
		},
		func(w wrapper.FactoryWrapper) {
			w.(dummyClusterCacheFactory).setClusterCache(cache)
		})
}

func (f *dummyClusterCacheFactoryImpl) setClusterCache(cache cluster.ClusterCache) {
	f.cache = cache
}

func (f *dummyClusterCacheFactoryImpl) NewClusterCache(ctx context.Context, options ...rest.HTTPClientOption) cluster.ClusterCache {
	return f.cache
}

func NewDummyClusterCache() cluster.ClusterCache {
	return &dummyClusterCache{
		clusters: clusters,
	}
}

func NewDummyClusterCacheWithClusters(value map[string]cluster.Cluster) cluster.ClusterCache {
	return &dummyClusterCache{
		clusters: value,
	}
}

type dummyClusterCache struct {
	clusters map[string]cluster.Cluster
}

func (c *dummyClusterCache) RLock()   {}
func (c *dummyClusterCache) RUnlock() {}

func (c *dummyClusterCache) Start(ctx context.Context) error {
	return nil
}

func (c *dummyClusterCache) Stop() {}

func (c *dummyClusterCache) Clusters() map[string]cluster.Cluster {
	return c.clusters
}

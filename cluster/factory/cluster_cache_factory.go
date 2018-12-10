package factory

import (
	"context"
	"time"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/rest"
)

type ClusterCacheFactoryConfiguration interface {
	manager.TokenManagerConfiguration
	GetClusterServiceURL() string
	GetClusterCacheRefreshInterval() time.Duration
}

// NewClusterCacheFactory returns the default cluster cache factory.
func NewClusterCacheFactory(context servicecontext.ServiceContext, config ClusterCacheFactoryConfiguration) service.ClusterCacheFactory {
	factory := &clusterCacheFactoryImpl{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
	return factory
}

type clusterCacheFactoryImpl struct {
	base.BaseService
	config ClusterCacheFactoryConfiguration
}

// NewClusterCache creates a new cluster cache
func (f *clusterCacheFactoryImpl) NewClusterCache(ctx context.Context, options ...rest.HTTPClientOption) cluster.ClusterCache {
	return cluster.NewCache(f.config, options...)
}

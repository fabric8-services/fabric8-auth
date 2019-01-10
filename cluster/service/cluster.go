package service

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/cluster"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	clusterclient "github.com/fabric8-services/fabric8-cluster-client/cluster"
	goaclient "github.com/goadesign/goa/client"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"net/http"
	"net/url"
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
func NewClusterService(context servicecontext.ServiceContext, config clusterServiceConfig) service.ClusterService {
	return &clusterService{
		BaseService: base.NewBaseService(context),
		config:      config,
	}
}

// Clusters returns cached map of OpenShift clusters
func (s *clusterService) Clusters(ctx context.Context, options ...rest.HTTPClientOption) ([]cluster.Cluster, error) {
	_, err := Start(ctx, s.Factories().ClusterCacheFactory(), options...)
	if err != nil {
		return nil, err
	}
	clusterCache.RLock()
	defer clusterCache.RUnlock()

	return Clusters(clusterCache.Clusters()), nil
}

// ClusterByURL returns the cached cluster for the given cluster API URL
func (s *clusterService) ClusterByURL(ctx context.Context, url string, options ...rest.HTTPClientOption) (*cluster.Cluster, error) {
	_, err := Start(ctx, s.Factories().ClusterCacheFactory(), options...)
	if err != nil {
		return nil, err
	}
	clusterCache.RLock()
	defer clusterCache.RUnlock()

	return ClusterByURL(clusterCache.Clusters(), url), nil
}

func (s *clusterService) Status(ctx context.Context, options ...rest.HTTPClientOption) (bool, error) {
	return Start(ctx, s.Factories().ClusterCacheFactory(), options...)
}

func (s *clusterService) Stop() {
	if clusterCache != nil && atomic.LoadUint32(&started) == 1 {
		startLock.Lock()
		defer startLock.Unlock()
		clusterCache.Stop()
		started = uint32(0)
	}
}

// LinkIdentityToCluster links Identity To Cluster using Cluster URL
func (s *clusterService) LinkIdentityToCluster(ctx context.Context, identityID uuid.UUID, clusterURL string, options ...rest.HTTPClientOption) error {
	signer := newJWTSASigner(ctx, s.config, options...)
	remoteClusterService, err := signer.createSignedClient()
	if err != nil {
		return errors.Wrapf(err, "failed to create JWT signer for cluster service")
	}
	identityToClusterData := &clusterclient.LinkIdentityToClusterData{
		ClusterURL: clusterURL,
		IdentityID: identityID.String(),
	}
	res, err := remoteClusterService.LinkIdentityToClusterClusters(goasupport.ForwardContextRequestID(ctx), clusterclient.LinkIdentityToClusterClustersPath(), identityToClusterData)
	if err != nil {
		return errors.Wrapf(err, "failed to link identity %s to cluster having url %s", identityID, clusterURL)
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body) // To prevent FDs leaks
	if res.StatusCode != http.StatusNoContent {
		log.Error(ctx, map[string]interface{}{
			"identity_id":     identityID,
			"cluster_url":     clusterURL,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to link identity to cluster in cluster management service")
		return errors.Errorf("failed to link identity to cluster in cluster management service. Response status: %s. Response body: %s", res.Status, bodyString)
	}
	return nil
}

// UnlinkIdentityFromCluster removes linked Identity from Cluster using Cluster URL
func (s *clusterService) UnlinkIdentityFromCluster(ctx context.Context, identityID uuid.UUID, clusterURL string, options ...rest.HTTPClientOption) error {
	signer := newJWTSASigner(ctx, s.config, options...)
	remoteClusterService, err := signer.createSignedClient()
	if err != nil {
		return err
	}
	identityToClusterData := &clusterclient.UnLinkIdentityToClusterdata{
		ClusterURL: clusterURL,
		IdentityID: identityID.String(),
	}
	res, err := remoteClusterService.RemoveIdentityToClusterLinkClusters(goasupport.ForwardContextRequestID(ctx), clusterclient.RemoveIdentityToClusterLinkClustersPath(), identityToClusterData)
	if err != nil {
		return errors.Wrapf(err, "failed to unlink identity %s from cluster having url %s", identityID, clusterURL)
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body) // To prevent FDs leaks
	if res.StatusCode != http.StatusNoContent {
		log.Error(ctx, map[string]interface{}{
			"identity_id":     identityID,
			"cluster_url":     clusterURL,
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to remove identity cluster relationship in cluster management service")
		return errors.Errorf("failed to unlink identity to cluster in cluster management service. Response status: %s. Response body: %s", res.Status, bodyString)
	}
	return nil
}

// Start initializes the default Cluster cache if it's not initialized already
// Cache initialization loads the list of clusters from the cluster management service and starts regular cache refresher
func Start(ctx context.Context, factory service.ClusterCacheFactory, options ...rest.HTTPClientOption) (bool, error) {
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
			return clusterCache != nil && started == uint32(1), err
		}
	}
	return clusterCache != nil && started == uint32(1), nil
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
	for apiURL, c := range clusters {
		if strings.HasPrefix(rest.AddTrailingSlashToURL(url), apiURL) {
			return &c
		}
	}

	return nil
}

type saSigner interface {
	createSignedClient() (*clusterclient.Client, error)
}

type jwtSASigner struct {
	ctx     context.Context
	config  clusterConfig
	options []rest.HTTPClientOption
}

func newJWTSASigner(ctx context.Context, config clusterConfig, options ...rest.HTTPClientOption) saSigner {
	return &jwtSASigner{ctx, config, options}
}

// CreateSignedClient creates a client with a JWT signer which uses the Auth Service Account token
func (c jwtSASigner) createSignedClient() (*clusterclient.Client, error) {
	cln, err := c.createClient(c.ctx)
	if err != nil {
		return nil, err
	}
	m, err := manager.DefaultManager(c.config)
	if err != nil {
		return nil, err
	}
	signer := m.AuthServiceAccountSigner()
	cln.SetJWTSigner(signer)
	return cln, nil
}

func (c jwtSASigner) createClient(ctx context.Context) (*clusterclient.Client, error) {
	u, err := url.Parse(c.config.GetClusterServiceURL())
	if err != nil {
		return nil, err
	}

	httpClient := http.DefaultClient

	if c.options != nil {
		for _, opt := range c.options {
			opt(httpClient)
		}
	}
	cln := clusterclient.New(goaclient.HTTPClientDoer(httpClient))

	cln.Host = u.Host
	cln.Scheme = u.Scheme
	return cln, nil
}

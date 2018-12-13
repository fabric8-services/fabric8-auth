package cluster

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-cluster-client/cluster"

	goaclient "github.com/goadesign/goa/client"
	"github.com/pkg/errors"
)

type clusterConfig interface {
	manager.TokenManagerConfiguration
	GetClusterServiceURL() string
	GetClusterCacheRefreshInterval() time.Duration
}

type ClusterCache interface {
	RLock()
	RUnlock()
	Clusters() map[string]Cluster
	Start(ctx context.Context) error
	Stop()
}

type cache struct {
	sync.RWMutex

	config    clusterConfig
	options   []rest.HTTPClientOption
	refresher *time.Ticker
	stopCh    chan bool
	clusters  map[string]Cluster
}

func NewCache(config clusterConfig, options ...rest.HTTPClientOption) ClusterCache {
	return &cache{
		config:    config,
		refresher: time.NewTicker(config.GetClusterCacheRefreshInterval()),
		options:   options,
	}
}

// start loads the list of clusters from Cluster Management Service into the cluster cache and initializes regular cache refreshing
func (c *cache) Start(ctx context.Context) error {
	err := c.refreshCache(ctx)
	if err != nil {
		return err
	}

	c.stopCh = make(chan bool, 1)
	go func() {
		defer log.Info(nil, map[string]interface{}{}, "cluster cache refresher stopped")
		log.Info(nil, map[string]interface{}{"interval": c.config.GetClusterCacheRefreshInterval()}, "cluster cache refresher started")
		for {
			select {
			case <-c.refresher.C:
				err := c.refreshCache(context.Background())
				if err != nil {
					log.Error(nil, map[string]interface{}{"err": err}, "failed to load the list of clusters during cache refresh")
				}
			case <-c.stopCh:
				return
			}
		}
	}()
	return nil
}

func (c *cache) Stop() {
	if c.stopCh != nil {
		c.stopCh <- true
	}
}

func (c *cache) Clusters() map[string]Cluster {
	return c.clusters
}

func (c *cache) refreshCache(ctx context.Context) error {
	log.Info(ctx, nil, "refreshing cached list of clusters...")
	clusters, err := c.fetchClusters(ctx)
	if err != nil {
		return err
	}
	c.Lock()
	defer c.Unlock()
	c.clusters = clusters
	log.Info(ctx, nil, "refreshed cached list of clusters")
	return nil
}

// fetchClusters fetches a new list of clusters from Cluster Management Service
func (c *cache) fetchClusters(ctx context.Context) (map[string]Cluster, error) {
	cln, err := c.createClientWithServiceAccountSigner(ctx)
	if err != nil {
		return nil, err
	}

	res, err := cln.ShowAuthClientClusters(goasupport.ForwardContextRequestID(ctx), cluster.ShowAuthClientClustersPath())
	if err != nil {
		return nil, err
	}
	defer rest.CloseResponse(res)

	if res.StatusCode != http.StatusOK {
		bodyString := rest.ReadBody(res.Body)
		log.Error(ctx, map[string]interface{}{
			"response_status": res.Status,
			"response_body":   bodyString,
		}, "unable to get clusters from Cluster Management Service")
		return nil, errors.Errorf("unable to get clusters from Cluster Management Service. Response status: %s. Response body: %s", res.Status, bodyString)
	}

	clusters, err := cln.DecodeFullClusterList(res)
	if err != nil {
		return nil, err
	}

	clusterMap := map[string]Cluster{}
	if clusters.Data != nil {
		for _, d := range clusters.Data {
			cls := Cluster{
				Name:                   d.Name,
				APIURL:                 d.APIURL,
				AppDNS:                 d.AppDNS,
				ConsoleURL:             d.ConsoleURL,
				LoggingURL:             d.LoggingURL,
				MetricsURL:             d.MetricsURL,
				TokenProviderID:        d.TokenProviderID,
				AuthClientDefaultScope: d.AuthClientDefaultScope,
				AuthClientID:           d.AuthClientID,
				AuthClientSecret:       d.AuthClientSecret,
				ServiceAccountUsername: d.ServiceAccountUsername,
				ServiceAccountToken:    d.ServiceAccountToken,
				CapacityExhausted:      d.CapacityExhausted,
			}
			clusterMap[rest.AddTrailingSlashToURL(cls.APIURL)] = cls
		}
	}
	return clusterMap, nil
}

// createClientWithSASigner creates a client with a JWT signer which uses the Auth Service Account token
func (c *cache) createClientWithServiceAccountSigner(ctx context.Context) (*cluster.Client, error) {
	cln, err := c.createClient(ctx)
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

func (c *cache) createClient(ctx context.Context) (*cluster.Client, error) {
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
	cln := cluster.New(goaclient.HTTPClientDoer(httpClient))

	cln.Host = u.Host
	cln.Scheme = u.Scheme
	return cln, nil
}

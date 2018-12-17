package cluster

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-cluster-client/cluster"
	goaclient "github.com/goadesign/goa/client"
	"net/http"
	"net/url"
)

// Cluster represents an OpenShift cluster configuration
type Cluster struct {
	Name                   string `mapstructure:"name"`
	APIURL                 string `mapstructure:"api-url"`
	ConsoleURL             string `mapstructure:"console-url"` // Optional in oso-clusters.conf
	MetricsURL             string `mapstructure:"metrics-url"` // Optional in oso-clusters.conf
	LoggingURL             string `mapstructure:"logging-url"` // Optional in oso-clusters.conf
	AppDNS                 string `mapstructure:"app-dns"`
	ServiceAccountToken    string `mapstructure:"service-account-token"`
	ServiceAccountUsername string `mapstructure:"service-account-username"`
	TokenProviderID        string `mapstructure:"token-provider-id"`
	AuthClientID           string `mapstructure:"auth-client-id"`
	AuthClientSecret       string `mapstructure:"auth-client-secret"`
	AuthClientDefaultScope string `mapstructure:"auth-client-default-scope"`
	CapacityExhausted      bool   `mapstructure:"capacity-exhausted"` // Optional in oso-clusters.conf ('false' by default)
}

type SASigner interface {
	CreateSignedClient() (*cluster.Client, error)
}

type JWTSASigner struct {
	ctx     context.Context
	config  clusterConfig
	options []rest.HTTPClientOption
}

func NewJWTSASigner(ctx context.Context, config clusterConfig, options ...rest.HTTPClientOption) SASigner {
	return &JWTSASigner{ctx, config, options}
}

// CreateSignedClient creates a client with a JWT signer which uses the Auth Service Account token
func (c JWTSASigner) CreateSignedClient() (*cluster.Client, error) {
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

func (c JWTSASigner) createClient(ctx context.Context) (*cluster.Client, error) {
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

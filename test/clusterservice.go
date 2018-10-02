package test

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/cluster"
	clusterservice "github.com/fabric8-services/fabric8-auth/cluster/service"
	"github.com/fabric8-services/fabric8-auth/rest"
	testservice "github.com/fabric8-services/fabric8-auth/test/service"

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

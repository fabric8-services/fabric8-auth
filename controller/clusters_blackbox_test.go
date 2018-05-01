package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	authrest "github.com/fabric8-services/fabric8-auth/rest"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestClustersREST struct {
	testsuite.UnitTestSuite
}

func TestRunClustersREST(t *testing.T) {
	suite.Run(t, &TestClustersREST{UnitTestSuite: testsuite.NewUnitTestSuite()})
}

func (rest *TestClustersREST) SecuredControllerWithServiceAccount(serviceAccount account.Identity) (*goa.Service, *ClustersController) {
	svc := testsupport.ServiceAsServiceAccountUser("Token-Service", serviceAccount)
	return svc, NewClustersController(svc, rest.Config)
}

func (rest *TestClustersREST) TestShowForServiceAccountsOK() {
	require.True(rest.T(), len(rest.Config.GetOSOClusters()) > 0)
	rest.checkShowForServiceAccount("fabric8-oso-proxy")
	rest.checkShowForServiceAccount("fabric8-tenant")
	rest.checkShowForServiceAccount("fabric8-jenkins-idler")
	rest.checkShowForServiceAccount("fabric8-jenkins-proxy")
}

func (rest *TestClustersREST) checkShowForServiceAccount(saName string) {
	sa := account.Identity{
		Username: saName,
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)
	_, clusters := test.ShowClustersOK(rest.T(), service.Context, service, controller)
	require.NotNil(rest.T(), clusters)
	require.NotNil(rest.T(), clusters.Data)
	require.Equal(rest.T(), len(rest.Config.GetOSOClusters()), len(clusters.Data))
	for _, cluster := range clusters.Data {
		configCluster := rest.Config.GetOSOClusterByURL(cluster.APIURL)
		require.NotNil(rest.T(), configCluster)
		require.Equal(rest.T(), configCluster.Name, cluster.Name)
		require.Equal(rest.T(), authrest.AddTrailingSlashToURL(configCluster.APIURL), cluster.APIURL)
		require.Equal(rest.T(), authrest.AddTrailingSlashToURL(configCluster.ConsoleURL), cluster.ConsoleURL)
		require.Equal(rest.T(), authrest.AddTrailingSlashToURL(configCluster.MetricsURL), cluster.MetricsURL)
		require.Equal(rest.T(), authrest.AddTrailingSlashToURL(configCluster.LoggingURL), cluster.LoggingURL)
		require.Equal(rest.T(), configCluster.AppDNS, cluster.AppDNS)
		require.Equal(rest.T(), configCluster.CapacityExhausted, cluster.CapacityExhausted)
	}
}

func (rest *TestClustersREST) TestShowForUnknownSAFails() {
	sa := account.Identity{
		Username: "unknown-sa",
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)
	test.ShowClustersUnauthorized(rest.T(), service.Context, service, controller)
}

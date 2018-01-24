package controller_test

import (
	"testing"

	. "github.com/fabric8-services/fabric8-auth/controller"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app/test"
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
		configCluster, ok := rest.Config.GetOSOClusters()[cluster.APIURL]
		require.True(rest.T(), ok)
		require.Equal(rest.T(), configCluster.Name, cluster.Name)
		require.Equal(rest.T(), configCluster.APIURL, cluster.APIURL)
		require.Equal(rest.T(), configCluster.AppDNS, cluster.AppDNS)
	}
}

func (rest *TestClustersREST) TestShowForUnknownSAFails() {
	sa := account.Identity{
		Username: "unknown-sa",
	}
	service, controller := rest.SecuredControllerWithServiceAccount(sa)
	test.ShowClustersUnauthorized(rest.T(), service.Context, service, controller)
}

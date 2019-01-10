package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/suite"
)

type TestClustersREST struct {
	testsuite.UnitTestSuite
}

func TestRunClustersREST(t *testing.T) {
	suite.Run(t, &TestClustersREST{UnitTestSuite: testsuite.NewUnitTestSuite()})
}

func (rest *TestClustersREST) UnsecuredController() (*goa.Service, *ClustersController) {
	svc := goa.New("Cluster-Service")
	return svc, NewClustersController(svc, rest.Config)
}

func (rest *TestClustersREST) TestShowForServiceAccountsFails() {
	// The controller should be available. It should fail because the is no cluster service available to proxy to.
	service, controller := rest.UnsecuredController()
	test.ShowClustersBadGateway(rest.T(), service.Context, service, controller)
}

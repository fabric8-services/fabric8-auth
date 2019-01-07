package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testservice "github.com/fabric8-services/fabric8-auth/test/service"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/suite"
)

type ClustersControllerTestSuite struct {
	gormtestsupport.DBTestSuite
	clusterServiceMock *testservice.ClusterServiceMock
}

func TestClusterController(t *testing.T) {
	suite.Run(t, &ClustersControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *ClustersControllerTestSuite) UnsecuredController() (*goa.Service, *ClustersController) {
	svc := goa.New("Cluster-Service")
	return svc, NewClustersController(svc, s.Application, s.Configuration)
}

func (s *ClustersControllerTestSuite) SecuredController(identity *repository.Identity) (*goa.Service, *ClustersController) {
	svc := testsupport.ServiceAsServiceAccountUser("Cluster-Service", *identity)
	return svc, NewClustersController(svc, s.Application, s.Configuration)
}

func (s *ClustersControllerTestSuite) TestShowForServiceAccountsFails() {
	// The controller should be available. It should fail because the is no cluster service available to proxy to.
	service, controller := s.UnsecuredController()
	test.ShowClustersBadGateway(s.T(), service.Context, service, controller)
}

func (s *ClustersControllerTestSuite) TestLinkExistingIdentitiesToCluster() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		sa := &repository.Identity{
			Username: token.Migration,
			ID:       uuid.NewV4(),
		}
		svc, ctrl := s.SecuredController(sa)

		// when/then
		test.LinkExistingIdentitiesToClusterClustersAccepted(t, svc.Context, svc, ctrl)
	})

	s.T().Run("unauthorized", func(t *testing.T) {
		// given
		sa := &repository.Identity{
			Username: "unknown",
			ID:       uuid.NewV4(),
		}
		svc, ctrl := s.SecuredController(sa)

		// when/then
		test.LinkExistingIdentitiesToClusterClustersUnauthorized(t, svc.Context, svc, ctrl)
	})
}

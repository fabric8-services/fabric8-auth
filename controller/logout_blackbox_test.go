package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type LogoutControllerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestLogoutControllerTestSuite(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &LogoutControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (s *LogoutControllerTestSuite) UnSecuredController() (*goa.Service, *controller.LogoutController) {
	svc := testsupport.ServiceAsUser("Logout-Service", testsupport.TestIdentity)
	return svc, controller.NewLogoutController(svc, s.Application)
}

func (s *LogoutControllerTestSuite) TestLogoutRedirects() {
	// given
	svc, ctrl := s.UnSecuredController()
	redirect := "http://domain.com"
	// when
	resp := test.LogoutLogoutTemporaryRedirect(s.T(), svc.Context, svc, ctrl, &redirect)
	// then
	assert.Equal(s.T(), resp.Header().Get("Cache-Control"), "no-cache")
}

func (s *LogoutControllerTestSuite) TestLogoutWithoutReffererAndRedirectParamsBadRequest() {
	// given
	svc, ctrl := s.UnSecuredController()
	// when/then
	test.LogoutLogoutBadRequest(s.T(), svc.Context, svc, ctrl, nil)
}

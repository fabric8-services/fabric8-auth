package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestNamedUsersController(t *testing.T) {
	suite.Run(t, &NamedUsersControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type NamedUsersControllerTestSuite struct {
	gormtestsupport.DBTestSuite
	tenantService *dummyTenantService
}

func (s *NamedUsersControllerTestSuite) SetupTest() {
	s.DBTestSuite.SetupTest()
	s.tenantService = &dummyTenantService{}
}

func (s *NamedUsersControllerTestSuite) SecuredServiceAccountController(identity repository.Identity) (*goa.Service, *NamedusersController) {
	svc := testsupport.ServiceAsServiceAccountUser("Namedusers-ServiceAccount-Service", identity)
	controller := NewNamedusersController(svc, s.Application, s.Configuration, s.tenantService)
	return svc, controller
}

func (s *NamedUsersControllerTestSuite) SecuredController(identity repository.Identity) (*goa.Service, *NamedusersController) {
	svc := testsupport.ServiceAsUser("Users-Service", identity)
	controller := NewNamedusersController(svc, s.Application, s.Configuration, s.tenantService)
	return svc, controller
}

func (s *NamedUsersControllerTestSuite) TestDeprovisionOK() {
	// OK if tenant service succeed
	s.checkDeprovisionOK()

	// OK if tenant service failed
	s.tenantService.identityID = uuid.NewV4()
	s.tenantService.error = errors.NewInternalErrorFromString(nil, "tenant service failed")
	s.checkDeprovisionOK()
}

func (s *NamedUsersControllerTestSuite) TestDeprovisionFailsForUnknownUser() {
	svc, controller := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
	test.DeprovisionNamedusersNotFound(s.T(), svc.Context, svc, controller, uuid.NewV4().String())
}

func (s *NamedUsersControllerTestSuite) TestDeprovisionFailsForUnauthorizedIdentity() {
	userToDeprovision := s.Graph.CreateUser()

	// Another service account can't deprovision
	svc, controller := s.SecuredServiceAccountController(testsupport.TestTenantIdentity)
	test.DeprovisionNamedusersForbidden(s.T(), svc.Context, svc, controller, userToDeprovision.Identity().Username)

	// Regular user can't deprovision either
	svc, controller = s.SecuredController(*s.Graph.CreateUser().Identity())
	test.DeprovisionNamedusersForbidden(s.T(), svc.Context, svc, controller, userToDeprovision.Identity().Username)

	// If no token present in the context then fails too
	_, controller = s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
	test.DeprovisionNamedusersForbidden(s.T(), nil, nil, controller, userToDeprovision.Identity().Username)
}

func (s *NamedUsersControllerTestSuite) checkDeprovisionOK() {
	userToDeprovision := s.Graph.CreateUser()
	userToStayIntact := s.Graph.CreateUser()

	svc, controller := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
	_, result := test.DeprovisionNamedusersOK(s.T(), svc.Context, svc, controller, userToDeprovision.Identity().Username)

	// Check if tenant service was called
	assert.Equal(s.T(), userToDeprovision.IdentityID(), s.tenantService.identityID)
	assert.Equal(s.T(), userToDeprovision.User().ID.String(), *result.Data.Attributes.UserID)
	assert.Equal(s.T(), userToDeprovision.IdentityID().String(), *result.Data.Attributes.IdentityID)

	// Check if user was deprovisioned
	loadedUser := s.Graph.LoadUser(userToDeprovision.IdentityID())
	assert.Equal(s.T(), true, loadedUser.User().Deprovisioned)
	userToDeprovision.Identity().User.Deprovisioned = true
	testsupport.AssertIdentityEqual(s.T(), userToDeprovision.Identity(), loadedUser.Identity())

	// Check the other user was not deprovisioned
	loadedUser = s.Graph.LoadUser(userToStayIntact.IdentityID())
	assert.Equal(s.T(), false, loadedUser.User().Deprovisioned)
	testsupport.AssertIdentityEqual(s.T(), userToStayIntact.Identity(), loadedUser.Identity())
}

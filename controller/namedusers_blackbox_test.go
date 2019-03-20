package controller_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	"github.com/fabric8-services/fabric8-auth/gormapplication"

	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testservice "github.com/fabric8-services/fabric8-auth/test/generated/application/service"
	uuid "github.com/satori/go.uuid"

	"github.com/goadesign/goa"
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

func (s *NamedUsersControllerTestSuite) SecuredServiceAccountController(identity repository.Identity) (*goa.Service, *controller.NamedusersController) {
	svc := testsupport.ServiceAsServiceAccountUser("Namedusers-ServiceAccount-Service", identity)
	ctrl := controller.NewNamedusersController(svc, s.Application, s.Configuration, s.tenantService)
	return svc, ctrl
}

func (s *NamedUsersControllerTestSuite) SecuredController(identity repository.Identity) (*goa.Service, *controller.NamedusersController) {
	svc := testsupport.ServiceAsUser("Users-Service", identity)
	ctrl := controller.NewNamedusersController(svc, s.Application, s.Configuration, s.tenantService)
	return svc, ctrl
}

func (s *NamedUsersControllerTestSuite) TestDeprovision() { // for backward compatibility

	s.T().Run("ok", func(t *testing.T) {

		t.Run("without tenant failure", func(t *testing.T) {
			// OK if tenant service passed
			s.checkDeprovisionOK()
		})

		t.Run("with tenant failure", func(t *testing.T) {
			// OK if tenant service failed
			s.tenantService.identityID = uuid.NewV4()
			s.tenantService.error = errors.NewInternalErrorFromString(nil, "tenant service failed")
			s.checkDeprovisionOK()
		})
	})

	s.T().Run("failures", func(t *testing.T) {

		t.Run("not found", func(t *testing.T) {
			svc, ctrl := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
			test.DeprovisionNamedusersNotFound(s.T(), svc.Context, svc, ctrl, uuid.NewV4().String())
		})

		t.Run("forbidden", func(t *testing.T) {
			// given
			userToDeprovision := s.Graph.CreateUser()

			t.Run("other service", func(t *testing.T) {
				// Another service account can't deprovision
				svc, ctrl := s.SecuredServiceAccountController(testsupport.TestTenantIdentity)
				test.DeprovisionNamedusersForbidden(s.T(), svc.Context, svc, ctrl, userToDeprovision.Identity().Username)

			})

			t.Run("missing tokem", func(t *testing.T) {
				// If no token present in the context then fails too
				_, ctrl := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
				test.DeprovisionNamedusersForbidden(s.T(), nil, nil, ctrl, userToDeprovision.Identity().Username)
			})

			t.Run("regular user", func(t *testing.T) {
				// Regular user can't deprovision either
				svc, ctrl := s.SecuredController(*s.Graph.CreateUser().Identity())
				test.DeprovisionNamedusersForbidden(s.T(), svc.Context, svc, ctrl, userToDeprovision.Identity().Username)
			})

		})
	})

}

func (s *NamedUsersControllerTestSuite) checkDeprovisionOK() {
	userToDeprovision := s.Graph.CreateUser()
	userToStayIntact := s.Graph.CreateUser()

	svc, ctrl := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
	_, result := test.DeprovisionNamedusersOK(s.T(), svc.Context, svc, ctrl, userToDeprovision.Identity().Username)

	// Check if tenant service was called
	assert.Equal(s.T(), userToDeprovision.IdentityID(), s.tenantService.identityID)
	assert.Equal(s.T(), userToDeprovision.User().ID.String(), *result.Data.Attributes.UserID)
	assert.Equal(s.T(), userToDeprovision.IdentityID().String(), *result.Data.Attributes.IdentityID)

	// Check if user was banned
	loadedUser := s.Graph.LoadUser(userToDeprovision.IdentityID())
	assert.Equal(s.T(), true, loadedUser.User().Banned)
	userToDeprovision.Identity().User.Banned = true
	testsupport.AssertIdentityEqual(s.T(), userToDeprovision.Identity(), loadedUser.Identity())

	// Check the other user was not banned
	loadedUser = s.Graph.LoadUser(userToStayIntact.IdentityID())
	assert.Equal(s.T(), false, loadedUser.User().Banned)
	testsupport.AssertIdentityEqual(s.T(), userToStayIntact.Identity(), loadedUser.Identity())
}

func (s *NamedUsersControllerTestSuite) TestBan() {

	s.T().Run("ok", func(t *testing.T) {

		t.Run("without tenant failure", func(t *testing.T) {
			// OK if tenant service passed
			s.checkBanOK()
		})

		t.Run("with tenant failure", func(t *testing.T) {
			// OK if tenant service failed
			s.tenantService.identityID = uuid.NewV4()
			s.tenantService.error = errors.NewInternalErrorFromString(nil, "tenant service failed")
			s.checkBanOK()
		})
	})

	s.T().Run("failures", func(t *testing.T) {

		t.Run("not found", func(t *testing.T) {
			svc, ctrl := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
			test.BanNamedusersNotFound(s.T(), svc.Context, svc, ctrl, uuid.NewV4().String())
		})

		t.Run("forbidden", func(t *testing.T) {
			// given
			userToBan := s.Graph.CreateUser()

			t.Run("other service", func(t *testing.T) {
				// Another service account can't deprovision
				svc, ctrl := s.SecuredServiceAccountController(testsupport.TestTenantIdentity)
				test.BanNamedusersForbidden(s.T(), svc.Context, svc, ctrl, userToBan.Identity().Username)

			})

			t.Run("missing tokem", func(t *testing.T) {
				// If no token present in the context then fails too
				_, ctrl := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
				test.BanNamedusersForbidden(s.T(), nil, nil, ctrl, userToBan.Identity().Username)
			})

			t.Run("regular user", func(t *testing.T) {
				// Regular user can't deprovision either
				svc, ctrl := s.SecuredController(*s.Graph.CreateUser().Identity())
				test.BanNamedusersForbidden(s.T(), svc.Context, svc, ctrl, userToBan.Identity().Username)
			})

		})
	})

}

func (s *NamedUsersControllerTestSuite) checkBanOK() {
	userToBan := s.Graph.CreateUser()
	userToStayIntact := s.Graph.CreateUser()

	svc, ctrl := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
	_, result := test.BanNamedusersOK(s.T(), svc.Context, svc, ctrl, userToBan.Identity().Username)

	// Check if tenant service was called
	assert.Equal(s.T(), userToBan.IdentityID(), s.tenantService.identityID)
	assert.Equal(s.T(), userToBan.User().ID.String(), *result.Data.Attributes.UserID)
	assert.Equal(s.T(), userToBan.IdentityID().String(), *result.Data.Attributes.IdentityID)

	// Check if user was banned
	loadedUser := s.Graph.LoadUser(userToBan.IdentityID())
	assert.Equal(s.T(), true, loadedUser.User().Banned)
	userToBan.Identity().User.Banned = true
	testsupport.AssertIdentityEqual(s.T(), userToBan.Identity(), loadedUser.Identity())

	// Check the other user was not banned
	loadedUser = s.Graph.LoadUser(userToStayIntact.IdentityID())
	assert.Equal(s.T(), false, loadedUser.User().Banned)
	testsupport.AssertIdentityEqual(s.T(), userToStayIntact.Identity(), loadedUser.Identity())
}

func (s *NamedUsersControllerTestSuite) TestDeactivateUser() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		userServiceMock := testservice.NewUserServiceMock(t)
		app := gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithUserService(userServiceMock))
		svc := testsupport.ServiceAsServiceAccountUser("Users-Service", testsupport.TestOnlineRegistrationAppIdentity)
		ctrl := controller.NewNamedusersController(svc, app, s.Configuration, s.tenantService)
		identity := &repository.Identity{
			ID:       uuid.NewV4(),
			Username: "user-to-deactivate",
			User: repository.User{
				ID: uuid.NewV4(),
			},
		}
		var usernameArg string
		userServiceMock.DeactivateUserFunc = func(ctx context.Context, username string) (*repository.Identity, error) {
			usernameArg = username
			return identity, nil
		}
		// userServiceMock.DeactivateUserMock.Expect(svc.Context, identity.Username)
		// when
		test.DeactivateNamedusersOK(t, svc.Context, svc, ctrl, "user-to-deactivate")
		// then
		// verify that the `UserService.DeactivateUser` func was called once...
		assert.Equal(t, 1, int(userServiceMock.DeactivateUserCounter))
		// ... with the expected `username` argument
		assert.Equal(t, "user-to-deactivate", usernameArg)
	})

	s.T().Run("failures", func(t *testing.T) {

		t.Run("invalid service account", func(t *testing.T) {
			// given
			svc, ctrl := s.SecuredServiceAccountController(testsupport.TestAdminConsoleIdentity)
			// when
			test.DeactivateNamedusersForbidden(t, context.Background(), svc, ctrl, "missing-token-user")

		})

		t.Run("missing token", func(t *testing.T) {
			// given
			svc, ctrl := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
			// when
			test.DeactivateNamedusersForbidden(t, context.Background(), svc, ctrl, "missing-token-user")
		})

		t.Run("unknown identity", func(t *testing.T) {
			// given
			userServiceMock := testservice.NewUserServiceMock(t)
			app := gormapplication.NewGormDB(s.DB, s.Configuration, s.Wrappers, factory.WithUserService(userServiceMock))
			svc := testsupport.ServiceAsServiceAccountUser("Users-Service", testsupport.TestOnlineRegistrationAppIdentity)
			ctrl := controller.NewNamedusersController(svc, app, s.Configuration, s.tenantService)
			// defer userServiceMock.Finish()
			userServiceMock.DeactivateUserFunc = func(ctx context.Context, username string) (*repository.Identity, error) {
				return nil, errors.NewNotFoundErrorFromString("user not found")
			}
			// when
			test.DeactivateNamedusersNotFound(t, svc.Context, svc, ctrl, "unknown-user")
			// then
			// verify that the `UserService.DeactivateUser` func was called once...
			assert.Equal(t, 1, int(userServiceMock.DeactivateUserCounter))
		})
	})
}

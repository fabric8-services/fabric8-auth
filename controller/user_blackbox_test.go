package controller_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/authorization"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	token "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserControllerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestUserController(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &UserControllerTestSuite{})
}

func (s *UserControllerTestSuite) SecuredController(identity account.Identity) (*goa.Service, *UserController) {
	svc := testsupport.ServiceAsUser("User-Service", identity)
	// userInfoProvider := service.NewUserInfoProvider(s.Application.Identities(), s.Application.Users(), testtoken.TokenManager, s.Application)
	controller := NewUserController(svc, s.Application, s.Configuration, testtoken.TokenManager, nil)
	return svc, controller
}

func (s *UserControllerTestSuite) UnsecuredController() (*goa.Service, *UserController) {
	svc := goa.New("User-Service")
	controller := NewUserController(svc, s.Application, s.Configuration, testtoken.TokenManager, nil)
	return svc, controller
}

func (s *UserControllerTestSuite) TestShowUser() {

	s.T().Run("ok", func(t *testing.T) {

		t.Run("without conditional request headers", func(t *testing.T) {
			// given
			identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
			require.Nil(t, err)
			// when
			svc, userCtrl := s.SecuredController(identity)
			res, user := test.ShowUserOK(t, svc.Context, svc, userCtrl, nil, nil)
			// then
			s.assertCurrentUser(t, *user, identity, identity.User)
			s.assertResponseHeaders(t, res, identity.User)
		})

		t.Run("using if-modified-since header", func(t *testing.T) {
			// given
			identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
			require.Nil(t, err)
			// when
			svc, userCtrl := s.SecuredController(identity)
			ifModifiedSince := identity.User.UpdatedAt.Add(-1 * time.Hour).UTC().Format(http.TimeFormat)
			res, user := test.ShowUserOK(t, svc.Context, svc, userCtrl, &ifModifiedSince, nil)
			// then
			s.assertCurrentUser(t, *user, identity, identity.User)
			s.assertResponseHeaders(t, res, identity.User)
		})

		t.Run("using if-none-match header", func(t *testing.T) {
			// given
			identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
			require.Nil(t, err)
			// when
			svc, userCtrl := s.SecuredController(identity)
			ifNoneMatch := "foo"
			res, user := test.ShowUserOK(t, svc.Context, svc, userCtrl, nil, &ifNoneMatch)
			// then
			s.assertCurrentUser(t, *user, identity, identity.User)
			s.assertResponseHeaders(t, res, identity.User)
		})

		t.Run("private email", func(t *testing.T) {

			t.Run("not visible if private", func(t *testing.T) {
				s.checkPrivateEmailVisible(t, true)
			})

			t.Run("visible if not private", func(t *testing.T) {
				s.checkPrivateEmailVisible(t, false)
			})
		})

	})

	s.T().Run("not modified", func(t *testing.T) {

		t.Run("using if-modified-since header", func(t *testing.T) {
			// given
			identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
			require.Nil(t, err)
			// when
			svc, userCtrl := s.SecuredController(identity)
			ifModifiedSince := app.ToHTTPTime(identity.User.UpdatedAt)
			res := test.ShowUserNotModified(t, svc.Context, svc, userCtrl, &ifModifiedSince, nil)
			// then
			s.assertResponseHeaders(t, res, identity.User)
		})

		t.Run("using if-none-match header", func(t *testing.T) {
			// given
			identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
			require.Nil(t, err)

			// when
			svc, userCtrl := s.SecuredController(identity)
			ifNoneMatch := app.GenerateEntityTag(identity.User)
			res := test.ShowUserNotModified(t, svc.Context, svc, userCtrl, nil, &ifNoneMatch)
			// then
			s.assertResponseHeaders(t, res, identity.User)
		})
	})

	s.T().Run("unauthorized", func(t *testing.T) {

		s.T().Run("missing token", func(t *testing.T) {
			// given
			jwtToken := token.New(token.SigningMethodRS256)
			jwtToken.Claims.(token.MapClaims)["sub"] = uuid.NewV4().String()
			ctx := jwt.WithJWT(context.Background(), jwtToken)
			svc, userCtrl := s.UnsecuredController()
			// when/then
			test.ShowUserUnauthorized(t, ctx, svc, userCtrl, nil, nil)
		})

		s.T().Run("ID not a UUID", func(t *testing.T) {
			// given
			jwtToken := token.New(token.SigningMethodRS256)
			jwtToken.Claims.(token.MapClaims)["sub"] = "aa"
			ctx := jwt.WithJWT(context.Background(), jwtToken)
			svc, userCtrl := s.UnsecuredController()
			// when/then
			test.ShowUserUnauthorized(t, ctx, svc, userCtrl, nil, nil)
		})

		s.T().Run("token without identity", func(t *testing.T) {
			// given
			jwtToken := token.New(token.SigningMethodRS256)
			ctx := jwt.WithJWT(context.Background(), jwtToken)
			svc, userCtrl := s.UnsecuredController()
			// when/then
			test.ShowUserUnauthorized(t, ctx, svc, userCtrl, nil, nil)
		})

		s.T().Run("deprovisionned user", func(t *testing.T) {
			// given
			identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "TestShowDeprovisionedUserFails"+uuid.NewV4().String())
			require.NoError(t, err)
			svc, userCtrl := s.SecuredController(identity)
			// when
			rw, _ := test.ShowUserUnauthorized(t, svc.Context, svc, userCtrl, nil, nil)
			// then
			assert.Equal(t, "DEPROVISIONED description=\"Account has been deprovisioned\"", rw.Header().Get("WWW-Authenticate"))
			assert.Contains(t, "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
		})

		s.T().Run("", func(t *testing.T) {

		})

		s.T().Run("", func(t *testing.T) {

		})

	})
}

func (s *UserControllerTestSuite) TestListUserSpaces() {

	s.T().Run("ok", func(t *testing.T) {

		t.Run("single role on space", func(t *testing.T) {
			// given
			g := s.NewTestGraph()
			user := g.CreateUser()
			space := g.CreateSpace().AddAdmin(user)
			require.NotNil(t, user.Identity())
			identity := user.Identity()
			// when
			svc, userCtrl := s.SecuredController(*identity)
			_, spaces := test.ListSpacesUserOK(t, svc.Context, svc, userCtrl)
			// then
			require.Len(t, spaces.Data, 1)
			require.Equal(t, space.SpaceID(), spaces.Data[0].ID, 1)
			assert.Equal(t, authorization.SpaceAdminRole, spaces.Data[0].Attributes.Role, 1)
			assert.Equal(t, authorization.SpaceAdminRole, spaces.Data[0].Attributes.Role, 1)
			assert.ElementsMatch(t, spaces.Data[0].Attributes.Scopes, []string{
				authorization.ManageSpaceScope,
				authorization.ContributeSpaceScope,
				authorization.ViewSpaceScope})
		})
	})

}

func (s *UserControllerTestSuite) checkPrivateEmailVisible(t *testing.T, emailPrivate bool) {
	testUser := account.User{
		ID:           uuid.NewV4(),
		Email:        uuid.NewV4().String(),
		FullName:     "Test Developer",
		Cluster:      "Test Cluster",
		EmailPrivate: emailPrivate,
	}

	identity, err := testsupport.CreateTestUser(s.DB, &testUser)
	require.NoError(t, err)
	svc, userCtrl := s.SecuredController(identity)

	_, returnedUser := test.ShowUserOK(t, svc.Context, svc, userCtrl, nil, nil)
	require.NotNil(t, returnedUser)
	require.Equal(t, testUser.Email, *returnedUser.Data.Attributes.Email)
}

func (s *UserControllerTestSuite) assertCurrentUser(t *testing.T, actualUser app.User, expectedIdentity account.Identity, expectedUser account.User) {
	require.NotNil(t, actualUser)
	require.NotNil(t, actualUser.Data)
	require.NotNil(t, actualUser.Data.Attributes)
	assert.Equal(t, expectedUser.FullName, *actualUser.Data.Attributes.FullName)
	assert.Equal(t, expectedIdentity.Username, *actualUser.Data.Attributes.Username)
	assert.Equal(t, expectedUser.ImageURL, *actualUser.Data.Attributes.ImageURL)
	assert.Equal(t, expectedUser.Email, *actualUser.Data.Attributes.Email)
	assert.Equal(t, expectedIdentity.ProviderType, *actualUser.Data.Attributes.ProviderType)
}

func (s *UserControllerTestSuite) assertResponseHeaders(t *testing.T, res http.ResponseWriter, usr account.User) {
	require.NotNil(t, res.Header()[app.LastModified])
	assert.Equal(t, usr.UpdatedAt.Truncate(time.Second).UTC().Format(http.TimeFormat), res.Header()[app.LastModified][0])
	require.NotNil(t, res.Header()[app.CacheControl])
	assert.Equal(t, s.Configuration.GetCacheControlUser(), res.Header()[app.CacheControl][0])
	require.NotNil(t, res.Header()[app.ETag])
	assert.Equal(t, app.GenerateEntityTag(usr), res.Header()[app.ETag][0])

}

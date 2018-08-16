package controller_test

import (
	"context"
	"net/http"
	"testing"
	"time"

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

func (s *UserControllerTestSuite) TestCurrentAuthorizedMissingUUID() {
	resource.Require(s.T(), resource.UnitTest)
	jwtToken := token.New(token.SigningMethodRS256)
	ctx := jwt.WithJWT(context.Background(), jwtToken)

	svc, userCtrl := s.UnsecuredController()
	test.ShowUserUnauthorized(s.T(), ctx, svc, userCtrl, nil, nil)
}

func (s *UserControllerTestSuite) TestCurrentAuthorizedNonUUID() {
	// given
	jwtToken := token.New(token.SigningMethodRS256)
	jwtToken.Claims.(token.MapClaims)["sub"] = "aa"
	ctx := jwt.WithJWT(context.Background(), jwtToken)
	// when
	svc, userCtrl := s.UnsecuredController()
	// then
	test.ShowUserUnauthorized(s.T(), ctx, svc, userCtrl, nil, nil)
}

func (s *UserControllerTestSuite) TestCurrentAuthorizedMissingIdentity() {
	// given
	jwtToken := token.New(token.SigningMethodRS256)
	jwtToken.Claims.(token.MapClaims)["sub"] = uuid.NewV4().String()
	ctx := jwt.WithJWT(context.Background(), jwtToken)
	// when
	svc, userCtrl := s.UnsecuredController()
	// then
	test.ShowUserUnauthorized(s.T(), ctx, svc, userCtrl, nil, nil)
}

func (s *UserControllerTestSuite) TestCurrentAuthorizedOK() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	// when
	svc, userCtrl := s.SecuredController(identity)
	res, user := test.ShowUserOK(s.T(), svc.Context, svc, userCtrl, nil, nil)
	// then
	s.assertCurrentUser(*user, identity, identity.User)
	s.assertResponseHeaders(res, identity.User)
}

func (s *UserControllerTestSuite) TestShowDeprovisionedUserFails() {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "TestShowDeprovisionedUserFails"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	svc, userCtrl := s.SecuredController(identity)
	rw, _ := test.ShowUserUnauthorized(s.T(), svc.Context, svc, userCtrl, nil, nil)

	assert.Equal(s.T(), "DEPROVISIONED description=\"Account has been deprovisioned\"", rw.Header().Get("WWW-Authenticate"))
	assert.Contains(s.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
}

func (s *UserControllerTestSuite) TestCurrentAuthorizedOKUsingExpiredIfModifiedSinceHeader() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	// when
	svc, userCtrl := s.SecuredController(identity)
	ifModifiedSince := identity.User.UpdatedAt.Add(-1 * time.Hour).UTC().Format(http.TimeFormat)
	res, user := test.ShowUserOK(s.T(), svc.Context, svc, userCtrl, &ifModifiedSince, nil)
	// then
	s.assertCurrentUser(*user, identity, identity.User)
	s.assertResponseHeaders(res, identity.User)
}

func (s *UserControllerTestSuite) TestCurrentAuthorizedOKUsingExpiredIfNoneMatchHeader() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	// when
	svc, userCtrl := s.SecuredController(identity)
	ifNoneMatch := "foo"
	res, user := test.ShowUserOK(s.T(), svc.Context, svc, userCtrl, nil, &ifNoneMatch)
	// then
	s.assertCurrentUser(*user, identity, identity.User)
	s.assertResponseHeaders(res, identity.User)
}

func (s *UserControllerTestSuite) TestCurrentAuthorizedNotModifiedUsingIfModifiedSinceHeader() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	// when
	svc, userCtrl := s.SecuredController(identity)
	ifModifiedSince := app.ToHTTPTime(identity.User.UpdatedAt)
	res := test.ShowUserNotModified(s.T(), svc.Context, svc, userCtrl, &ifModifiedSince, nil)
	// then
	s.assertResponseHeaders(res, identity.User)
}

func (s *UserControllerTestSuite) TestCurrentAuthorizedNotModifiedUsingIfNoneMatchHeader() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	// when
	svc, userCtrl := s.SecuredController(identity)
	ifNoneMatch := app.GenerateEntityTag(identity.User)
	res := test.ShowUserNotModified(s.T(), svc.Context, svc, userCtrl, nil, &ifNoneMatch)
	// then
	s.assertResponseHeaders(res, identity.User)
}

func (s *UserControllerTestSuite) TestPrivateEmailVisibleIfNotPrivate() {
	s.checkPrivateEmailVisible(false)
}

func (s *UserControllerTestSuite) TestPrivateEmailVisibleIfPrivate() {
	s.checkPrivateEmailVisible(true)
}

func (s *UserControllerTestSuite) checkPrivateEmailVisible(emailPrivate bool) {
	testUser := account.User{
		ID:           uuid.NewV4(),
		Email:        uuid.NewV4().String(),
		FullName:     "Test Developer",
		Cluster:      "Test Cluster",
		EmailPrivate: emailPrivate,
	}

	identity, err := testsupport.CreateTestUser(s.DB, &testUser)
	require.NoError(s.T(), err)
	svc, userCtrl := s.SecuredController(identity)

	_, returnedUser := test.ShowUserOK(s.T(), svc.Context, svc, userCtrl, nil, nil)
	require.NotNil(s.T(), returnedUser)
	require.Equal(s.T(), testUser.Email, *returnedUser.Data.Attributes.Email)
}

func (s *UserControllerTestSuite) assertCurrentUser(actualUser app.User, expectedIdentity account.Identity, expectedUser account.User) {
	require.NotNil(s.T(), actualUser)
	require.NotNil(s.T(), actualUser.Data)
	require.NotNil(s.T(), actualUser.Data.Attributes)
	assert.Equal(s.T(), expectedUser.FullName, *actualUser.Data.Attributes.FullName)
	assert.Equal(s.T(), expectedIdentity.Username, *actualUser.Data.Attributes.Username)
	assert.Equal(s.T(), expectedUser.ImageURL, *actualUser.Data.Attributes.ImageURL)
	assert.Equal(s.T(), expectedUser.Email, *actualUser.Data.Attributes.Email)
	assert.Equal(s.T(), expectedIdentity.ProviderType, *actualUser.Data.Attributes.ProviderType)
}

func (s *UserControllerTestSuite) assertResponseHeaders(res http.ResponseWriter, usr account.User) {
	require.NotNil(s.T(), res.Header()[app.LastModified])
	assert.Equal(s.T(), usr.UpdatedAt.Truncate(time.Second).UTC().Format(http.TimeFormat), res.Header()[app.LastModified][0])
	require.NotNil(s.T(), res.Header()[app.CacheControl])
	assert.Equal(s.T(), s.Configuration.GetCacheControlUser(), res.Header()[app.CacheControl][0])
	require.NotNil(s.T(), res.Header()[app.ETag])
	assert.Equal(s.T(), app.GenerateEntityTag(usr), res.Header()[app.ETag][0])

}

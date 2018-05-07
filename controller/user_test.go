package controller_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/account/service"
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

type TestUserREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunUserREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestUserREST{})
}

func (rest *TestUserREST) SecuredController(identity account.Identity) (*goa.Service, *UserController) {
	svc := testsupport.ServiceAsUser("User-Service", identity)
	userInfoProvider := service.NewUserInfoProvider(rest.Application.Identities(), rest.Application.Users(), testtoken.TokenManager, rest.Application)
	controller := NewUserController(svc, userInfoProvider, rest.Application, testtoken.TokenManager, rest.Configuration)
	return svc, controller
}

func (rest *TestUserREST) UnsecuredController() (*goa.Service, *UserController) {
	svc := goa.New("User-Service")
	userInfoProvider := service.NewUserInfoProvider(rest.Application.Identities(), rest.Application.Users(), testtoken.TokenManager, rest.Application)
	controller := NewUserController(svc, userInfoProvider, rest.Application, testtoken.TokenManager, rest.Configuration)
	return svc, controller
}

func (rest *TestUserREST) TestCurrentAuthorizedMissingUUID() {
	resource.Require(rest.T(), resource.UnitTest)
	jwtToken := token.New(token.SigningMethodRS256)
	ctx := jwt.WithJWT(context.Background(), jwtToken)

	svc, userCtrl := rest.UnsecuredController()
	test.ShowUserUnauthorized(rest.T(), ctx, svc, userCtrl, nil, nil)
}

func (rest *TestUserREST) TestCurrentAuthorizedNonUUID() {
	// given
	jwtToken := token.New(token.SigningMethodRS256)
	jwtToken.Claims.(token.MapClaims)["sub"] = "aa"
	ctx := jwt.WithJWT(context.Background(), jwtToken)
	// when
	svc, userCtrl := rest.UnsecuredController()
	// then
	test.ShowUserUnauthorized(rest.T(), ctx, svc, userCtrl, nil, nil)
}

func (rest *TestUserREST) TestCurrentAuthorizedMissingIdentity() {
	// given
	jwtToken := token.New(token.SigningMethodRS256)
	jwtToken.Claims.(token.MapClaims)["sub"] = uuid.NewV4().String()
	ctx := jwt.WithJWT(context.Background(), jwtToken)
	// when
	svc, userCtrl := rest.UnsecuredController()
	// then
	test.ShowUserUnauthorized(rest.T(), ctx, svc, userCtrl, nil, nil)
}

func (rest *TestUserREST) TestCurrentAuthorizedOK() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(rest.T(), err)

	// when
	svc, userCtrl := rest.SecuredController(identity)
	res, user := test.ShowUserOK(rest.T(), svc.Context, svc, userCtrl, nil, nil)
	// then
	rest.assertCurrentUser(*user, identity, identity.User)
	rest.assertResponseHeaders(res, identity.User)
}

func (rest *TestUserREST) TestShowDeprovisionedUserFails() {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(rest.DB, "TestShowDeprovisionedUserFails"+uuid.NewV4().String())
	require.NoError(rest.T(), err)

	svc, userCtrl := rest.SecuredController(identity)
	rw, _ := test.ShowUserUnauthorized(rest.T(), svc.Context, svc, userCtrl, nil, nil)

	assert.Equal(rest.T(), "DEPROVISIONED description=\"Account has been deprovisioned\"", rw.Header().Get("WWW-Authenticate"))
	assert.Contains(rest.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
}

func (rest *TestUserREST) TestCurrentAuthorizedOKUsingExpiredIfModifiedSinceHeader() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(rest.T(), err)

	// when
	svc, userCtrl := rest.SecuredController(identity)
	ifModifiedSince := identity.User.UpdatedAt.Add(-1 * time.Hour).UTC().Format(http.TimeFormat)
	res, user := test.ShowUserOK(rest.T(), svc.Context, svc, userCtrl, &ifModifiedSince, nil)
	// then
	rest.assertCurrentUser(*user, identity, identity.User)
	rest.assertResponseHeaders(res, identity.User)
}

func (rest *TestUserREST) TestCurrentAuthorizedOKUsingExpiredIfNoneMatchHeader() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(rest.T(), err)

	// when
	svc, userCtrl := rest.SecuredController(identity)
	ifNoneMatch := "foo"
	res, user := test.ShowUserOK(rest.T(), svc.Context, svc, userCtrl, nil, &ifNoneMatch)
	// then
	rest.assertCurrentUser(*user, identity, identity.User)
	rest.assertResponseHeaders(res, identity.User)
}

func (rest *TestUserREST) TestCurrentAuthorizedNotModifiedUsingIfModifiedSinceHeader() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(rest.T(), err)

	// when
	svc, userCtrl := rest.SecuredController(identity)
	ifModifiedSince := app.ToHTTPTime(identity.User.UpdatedAt)
	res := test.ShowUserNotModified(rest.T(), svc.Context, svc, userCtrl, &ifModifiedSince, nil)
	// then
	rest.assertResponseHeaders(res, identity.User)
}

func (rest *TestUserREST) TestCurrentAuthorizedNotModifiedUsingIfNoneMatchHeader() {
	// given
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, "userTestCurrentAuthorizedOK"+uuid.NewV4().String())
	require.Nil(rest.T(), err)

	// when
	svc, userCtrl := rest.SecuredController(identity)
	ifNoneMatch := app.GenerateEntityTag(identity.User)
	res := test.ShowUserNotModified(rest.T(), svc.Context, svc, userCtrl, nil, &ifNoneMatch)
	// then
	rest.assertResponseHeaders(res, identity.User)
}

func (rest *TestUserREST) TestPrivateEmailVisibleIfNotPrivate() {
	rest.checkPrivateEmailVisible(false)
}

func (rest *TestUserREST) TestPrivateEmailVisibleIfPrivate() {
	rest.checkPrivateEmailVisible(true)
}

func (rest *TestUserREST) checkPrivateEmailVisible(emailPrivate bool) {
	testUser := account.User{
		ID:           uuid.NewV4(),
		Email:        uuid.NewV4().String(),
		FullName:     "Test Developer",
		Cluster:      "Test Cluster",
		EmailPrivate: emailPrivate,
	}

	identity, err := testsupport.CreateTestUser(rest.DB, &testUser)
	require.NoError(rest.T(), err)
	svc, userCtrl := rest.SecuredController(identity)

	_, returnedUser := test.ShowUserOK(rest.T(), svc.Context, svc, userCtrl, nil, nil)
	require.NotNil(rest.T(), returnedUser)
	require.Equal(rest.T(), testUser.Email, *returnedUser.Data.Attributes.Email)
}

func (rest *TestUserREST) assertCurrentUser(actualUser app.User, expectedIdentity account.Identity, expectedUser account.User) {
	require.NotNil(rest.T(), actualUser)
	require.NotNil(rest.T(), actualUser.Data)
	require.NotNil(rest.T(), actualUser.Data.Attributes)
	assert.Equal(rest.T(), expectedUser.FullName, *actualUser.Data.Attributes.FullName)
	assert.Equal(rest.T(), expectedIdentity.Username, *actualUser.Data.Attributes.Username)
	assert.Equal(rest.T(), expectedUser.ImageURL, *actualUser.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), expectedUser.Email, *actualUser.Data.Attributes.Email)
	assert.Equal(rest.T(), expectedIdentity.ProviderType, *actualUser.Data.Attributes.ProviderType)
}

func (rest *TestUserREST) assertResponseHeaders(res http.ResponseWriter, usr account.User) {
	require.NotNil(rest.T(), res.Header()[app.LastModified])
	assert.Equal(rest.T(), usr.UpdatedAt.Truncate(time.Second).UTC().Format(http.TimeFormat), res.Header()[app.LastModified][0])
	require.NotNil(rest.T(), res.Header()[app.CacheControl])
	assert.Equal(rest.T(), rest.Configuration.GetCacheControlUser(), res.Header()[app.CacheControl][0])
	require.NotNil(rest.T(), res.Header()[app.ETag])
	assert.Equal(rest.T(), app.GenerateEntityTag(usr), res.Header()[app.ETag][0])

}

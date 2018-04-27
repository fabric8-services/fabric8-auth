package controller_test

import (
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/account/userinfo"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestUserInfoREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunUserInfoREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestUserInfoREST{})
}

func (rest *TestUserInfoREST) SecuredController(identity account.Identity) (*goa.Service, *UserinfoController) {
	svc := testsupport.ServiceAsUser("Userinfo-Service", identity)
	userInfoProvider := userinfo.NewUserInfoProvider(rest.Application.Identities(), rest.Application.Users(), testtoken.TokenManager, rest.Application)
	controller := NewUserinfoController(svc, userInfoProvider, rest.Application, testtoken.TokenManager)
	return svc, controller
}

func (rest *TestUserInfoREST) UnsecuredController() (*goa.Service, *UserinfoController) {
	svc := goa.New("Userinfo-Service")
	userInfoProvider := userinfo.NewUserInfoProvider(rest.Application.Identities(), rest.Application.Users(), testtoken.TokenManager, rest.Application)
	controller := NewUserinfoController(svc, userInfoProvider, rest.Application, testtoken.TokenManager)
	return svc, controller
}

func (rest *TestUserInfoREST) TestShowUserInfoOK() {
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(rest.DB, "userTestShowUserInfoOK"+uuid.Must(uuid.NewV4()).String())
	require.Nil(rest.T(), err)

	svc, ctrl := rest.SecuredController(identity)
	_, userInfo := test.ShowUserinfoOK(rest.T(), svc.Context, svc, ctrl)

	rest.assertCurrentUserInfo(userInfo, identity, identity.User)
}

func (rest *TestUserInfoREST) TestPrivateEmailVisibleIfNotPrivate() {
	rest.checkPrivateEmailVisible(false)
}

func (rest *TestUserInfoREST) TestPrivateEmailVisibleIfPrivate() {
	rest.checkPrivateEmailVisible(true)
}

func (rest *TestUserInfoREST) TestShowUserInfoFailsWithInvalidToken() {
	svc, ctrl := rest.UnsecuredController()
	test.ShowUserinfoUnauthorized(rest.T(), svc.Context, svc, ctrl)

	// Creates an unsigned Token without subject
	jwtToken := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, jwtgo.MapClaims{
		"given_name":         "someGivenName",
		"family_name":        "someFamilyName",
		"preferred_username": "someUserName",
		"email":              "someEmail",
	})
	ctx := jwt.WithJWT(svc.Context, jwtToken)

	_, err := test.ShowUserinfoUnauthorized(rest.T(), ctx, svc, ctrl)
	require.Equal(rest.T(), err.Errors[0].Detail, fmt.Sprintf("bad token"))

	// We are adding subject, but subject is not matching any of the identities that we have
	sub := uuid.Must(uuid.NewV4()).String()
	jwtToken.Claims.(jwtgo.MapClaims)["sub"] = sub
	_, err = test.ShowUserinfoUnauthorized(rest.T(), ctx, svc, ctrl)
	require.Equal(rest.T(), err.Errors[0].Detail, fmt.Sprintf("auth token contains id %s of unknown Identity\n", sub))
}

func (rest *TestUserInfoREST) TestShowUserinfoDeprovisionedUserFails() {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(rest.DB, "TestShowUserinfoDeprovisionedUserFails"+uuid.Must(uuid.NewV4()).String())
	require.NoError(rest.T(), err)

	svc, userCtrl := rest.SecuredController(identity)
	rw, _ := test.ShowUserinfoUnauthorized(rest.T(), svc.Context, svc, userCtrl)

	assert.Equal(rest.T(), "DEPROVISIONED description=\"Account has been deprovisioned\"", rw.Header().Get("WWW-Authenticate"))
	assert.Contains(rest.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
}

func (rest *TestUserInfoREST) checkPrivateEmailVisible(emailPrivate bool) {
	testUser := account.User{
		ID:           uuid.Must(uuid.NewV4()),
		Email:        uuid.Must(uuid.NewV4()).String(),
		FullName:     "Test Developer",
		Cluster:      "Test Cluster",
		EmailPrivate: emailPrivate,
	}

	identity, err := testsupport.CreateTestUser(rest.DB, &testUser)
	require.NoError(rest.T(), err)
	svc, ctrl := rest.SecuredController(identity)

	_, returnedUserinfo := test.ShowUserinfoOK(rest.T(), svc.Context, svc, ctrl)
	require.NotNil(rest.T(), returnedUserinfo)
	require.Equal(rest.T(), testUser.Email, *returnedUserinfo.Email)
}

func (rest *TestUserInfoREST) assertCurrentUserInfo(actualUser *app.UserInfo, expectedIdentity account.Identity, expectedUser account.User) {
	require.NotNil(rest.T(), actualUser)
	require.NotNil(rest.T(), actualUser.Email)
	require.Equal(rest.T(), expectedUser.Email, *actualUser.Email)
	require.NotNil(rest.T(), actualUser.PreferredUsername)
	require.Equal(rest.T(), expectedIdentity.Username, *actualUser.PreferredUsername)
	require.NotNil(rest.T(), actualUser.Sub)
	require.Equal(rest.T(), expectedIdentity.ID.String(), *actualUser.Sub)
	require.NotNil(rest.T(), actualUser.GivenName)
	require.NotNil(rest.T(), actualUser.FamilyName)
	givenName, familyName := account.SplitFullName(expectedUser.FullName)
	require.Equal(rest.T(), givenName, *actualUser.GivenName)
	require.Equal(rest.T(), familyName, *actualUser.FamilyName)
}

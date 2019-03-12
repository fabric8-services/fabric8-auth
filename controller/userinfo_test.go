package controller_test

import (
	"fmt"
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/authentication/account"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
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

type UserInfoControllerTestSuite struct {
	gormtestsupport.DBTestSuite
}

func TestUserInfoController(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &UserInfoControllerTestSuite{})
}

func (s *UserInfoControllerTestSuite) SecuredController(identity repository.Identity) (*goa.Service, *UserinfoController) {
	svc := testsupport.ServiceAsUser("Userinfo-Service", identity)
	controller := NewUserinfoController(svc, s.Application, testtoken.TokenManager)
	return svc, controller
}

func (s *UserInfoControllerTestSuite) UnsecuredController() (*goa.Service, *UserinfoController) {
	svc := goa.New("Userinfo-Service")
	controller := NewUserinfoController(svc, s.Application, testtoken.TokenManager)
	return svc, controller
}

func (s *UserInfoControllerTestSuite) TestShowUserInfoOK() {
	identity, err := testsupport.CreateTestIdentityAndUserWithDefaultProviderType(s.DB, "userTestShowUserInfoOK"+uuid.NewV4().String())
	require.Nil(s.T(), err)

	svc, ctrl := s.SecuredController(identity)
	_, userInfo := test.ShowUserinfoOK(s.T(), svc.Context, svc, ctrl)

	s.assertCurrentUserInfo(userInfo, identity, identity.User)
}

func (s *UserInfoControllerTestSuite) TestPrivateEmailVisibleIfNotPrivate() {
	s.checkPrivateEmailVisible(false)
}

func (s *UserInfoControllerTestSuite) TestPrivateEmailVisibleIfPrivate() {
	s.checkPrivateEmailVisible(true)
}

func (s *UserInfoControllerTestSuite) TestShowUserInfoFailsWithInvalidToken() {
	svc, ctrl := s.UnsecuredController()
	test.ShowUserinfoUnauthorized(s.T(), svc.Context, svc, ctrl)

	// Creates an unsigned Token without subject
	jwtToken := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, jwtgo.MapClaims{
		"given_name":         "someGivenName",
		"family_name":        "someFamilyName",
		"preferred_username": "someUserName",
		"email":              "someEmail",
	})
	ctx := jwt.WithJWT(svc.Context, jwtToken)

	_, err := test.ShowUserinfoUnauthorized(s.T(), ctx, svc, ctrl)
	require.Equal(s.T(), err.Errors[0].Detail, fmt.Sprintf("bad or missing token"))

	// We are adding subject, but subject is not matching any of the identities that we have
	sub := uuid.NewV4().String()
	jwtToken.Claims.(jwtgo.MapClaims)["sub"] = sub
	_, err = test.ShowUserinfoUnauthorized(s.T(), ctx, svc, ctrl)
	require.Equal(s.T(), err.Errors[0].Detail, fmt.Sprintf("auth token contains id %s of unknown Identity\n", sub))
}

func (s *UserInfoControllerTestSuite) TestShowUserinfoBannedUserFails() {
	identity, err := testsupport.CreateBannedTestIdentityAndUser(s.DB, "TestShowUserinfoBannedUserFails"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	svc, userCtrl := s.SecuredController(identity)
	rw, _ := test.ShowUserinfoUnauthorized(s.T(), svc.Context, svc, userCtrl)

	assert.Equal(s.T(), "DEPROVISIONED description=\"Account has been banned\"", rw.Header().Get("WWW-Authenticate"))
	assert.Contains(s.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
}

func (s *UserInfoControllerTestSuite) checkPrivateEmailVisible(emailPrivate bool) {
	testUser := repository.User{
		ID:           uuid.NewV4(),
		Email:        uuid.NewV4().String(),
		FullName:     "Test Developer",
		Cluster:      "Test Cluster",
		EmailPrivate: emailPrivate,
	}

	identity, err := testsupport.CreateTestUser(s.DB, &testUser)
	require.NoError(s.T(), err)
	svc, ctrl := s.SecuredController(identity)

	_, returnedUserinfo := test.ShowUserinfoOK(s.T(), svc.Context, svc, ctrl)
	require.NotNil(s.T(), returnedUserinfo)
	require.Equal(s.T(), testUser.Email, *returnedUserinfo.Email)
}

func (s *UserInfoControllerTestSuite) assertCurrentUserInfo(actualUser *app.UserInfo, expectedIdentity repository.Identity, expectedUser repository.User) {
	require.NotNil(s.T(), actualUser)
	require.NotNil(s.T(), actualUser.Email)
	require.Equal(s.T(), expectedUser.Email, *actualUser.Email)
	require.NotNil(s.T(), actualUser.PreferredUsername)
	require.Equal(s.T(), expectedIdentity.Username, *actualUser.PreferredUsername)
	require.NotNil(s.T(), actualUser.Sub)
	require.Equal(s.T(), expectedIdentity.ID.String(), *actualUser.Sub)
	require.NotNil(s.T(), actualUser.GivenName)
	require.NotNil(s.T(), actualUser.FamilyName)
	givenName, familyName := account.SplitFullName(expectedUser.FullName)
	require.Equal(s.T(), givenName, *actualUser.GivenName)
	require.Equal(s.T(), familyName, *actualUser.FamilyName)
}

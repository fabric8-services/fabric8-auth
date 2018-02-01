package controller_test

import (
	"testing"

	tkn "github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestUserInfoREST struct {
	suite.Suite
}

func TestRunUserInfoREST(t *testing.T) {
	resource.Require(t, resource.UnitTest)
	suite.Run(t, &TestUserInfoREST{})
}

func (s *TestUserInfoREST) UnSecuredController() (*goa.Service, *UserinfoController) {
	svc := goa.New("Status-Service")
	return svc, NewUserinfoController(svc, testtoken.TokenManager)
}

func (s *TestUserInfoREST) TestShowUserInfoOK() {

	t := s.T()
	svc, ctrl := s.UnSecuredController()
	require.NotNil(t, svc)
	require.NotNil(t, ctrl)

	tokenString, err := testtoken.GenerateSampleSignedTokenwithUserInfo()
	require.Nil(t, err)
	extracted, err := testtoken.TokenManager.Parse(svc.Context, *tokenString)
	require.Nil(t, err)
	require.NotNil(t, extracted)

	ctx := jwt.WithJWT(svc.Context, extracted)
	require.NotNil(t, ctx)

	_, userInfo := test.ShowUserinfoOK(t, ctx, svc, ctrl)

	require.Equal(t, *userInfo.GivenName, "someGivenName")
	require.Equal(t, *userInfo.FamilyName, "someFamilyName")
	require.Equal(t, *userInfo.Email, "someEmail")
	require.Equal(t, *userInfo.PreferredName, "someUserName")
	require.Equal(t, *userInfo.Sub, "someUUID")
}

func (s *TestUserInfoREST) TestShowUserInfoFailsWithInvalidToken() {
	t := s.T()
	svc, ctrl := s.UnSecuredController()

	// Creates an unsigned Token
	jwtToken := tkn.NewWithClaims(tkn.SigningMethodRS256, tkn.MapClaims{
		"sub":                uuid.NewV4().String(),
		"given_name":         "someGivenName",
		"family_name":        "someFamilyName",
		"preferred_username": "someUserName",
		"email":              "someEmail",
	})
	ctx := jwt.WithJWT(svc.Context, jwtToken)

	_, err := test.ShowUserinfoInternalServerError(t, ctx, svc, ctrl)
	require.NotNil(t, err)
	require.Equal(t, *err.Errors[0].Status, "500")
	require.Equal(t, err.Errors[0].Detail, "token contains an invalid number of segments")
}

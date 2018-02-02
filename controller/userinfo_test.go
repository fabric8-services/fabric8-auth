package controller_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/suite"
)

type TestUserInfoREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunUserInfoREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestUserInfoREST{})
}

// Might not be needed
func (s *TestUserInfoREST) UnSecuredController() (*goa.Service, *UserinfoController) {
	svc := goa.New("Status-Service")
	return svc, NewUserinfoController(svc, s.Application, testtoken.TokenManager)
}

func (rest *TestUserInfoREST) newUserinfoController(identity *account.Identity, user *account.User) *UserinfoController {
	return NewUserinfoController(goa.New("auth-test"), newGormTestBase(identity, user), testtoken.TokenManager)
}

func (s *TestUserInfoREST) TestShowUserInfoOK() {

	t := s.T()
	ctx, userinfoCtrl, usr, ident := s.initTest()

	_, userInfo := test.ShowUserinfoOK(t, ctx, nil, userinfoCtrl)

	require.Equal(t, *userInfo.Email, usr.Email)
	require.Equal(t, *userInfo.PreferredName, ident.Username)
	require.Equal(t, *userInfo.Sub, ident.ID.String())
	fullName := strings.Split(usr.FullName, " ")
	require.Equal(t, *userInfo.GivenName, fullName[0])
	require.Equal(t, *userInfo.FamilyName, fullName[1])
}

func (s *TestUserInfoREST) TestShowUserInfoFailsWithInvalidToken() {
	t := s.T()
	svc, ctrl := s.UnSecuredController()

	// Creates an unsigned Token
	sub := uuid.NewV4().String()
	jwtToken := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, jwtgo.MapClaims{
		"sub":                sub,
		"given_name":         "someGivenName",
		"family_name":        "someFamilyName",
		"preferred_username": "someUserName",
		"email":              "someEmail",
	})
	ctx := jwt.WithJWT(svc.Context, jwtToken)

	_, err := test.ShowUserinfoUnauthorized(t, ctx, svc, ctrl)
	require.Equal(t, err.Errors[0].Detail, fmt.Sprintf("Auth token contains id %s of unknown Identity\n", sub))
}

func (rest *TestUserInfoREST) initTest() (context.Context, app.UserinfoController, account.User, account.Identity) {
	jwtToken := jwtgo.New(jwtgo.SigningMethodRS256)
	jwtToken.Claims.(jwtgo.MapClaims)["sub"] = uuid.NewV4().String()
	ctx := jwt.WithJWT(context.Background(), jwtToken)
	usr := account.User{
		ID: uuid.NewV4(),
		Lifecycle: gormsupport.Lifecycle{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		FullName: "TestCurrentAuthorizedOK User",
		Email:    uuid.NewV4().String() + "email@domain.com",
	}
	ident := account.Identity{ID: uuid.NewV4(), Username: "TestUser", ProviderType: account.KeycloakIDP, User: usr, UserID: account.NullUUID{UUID: usr.ID, Valid: true}}
	userinfoCtrl := rest.newUserinfoController(&ident, &usr)
	return ctx, userinfoCtrl, usr, ident
}

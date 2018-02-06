package controller_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account/userprofile"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application"
	uuid "github.com/satori/go.uuid"

	"github.com/fabric8-services/fabric8-auth/account"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	jwtgo "github.com/dgrijalva/jwt-go"
)

type TestUserInfoREST struct {
	gormtestsupport.DBTestSuite
	userinfoStrategy string
}

func TestRunUserInfoREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestUserInfoREST{})
}

func (s *TestUserInfoREST) UnSecuredController() (*goa.Service, *UserinfoController) {
	svc := goa.New("Status-Service")
	accountService := newTestAccountProvider(s.Application)
	return svc, NewUserinfoController(svc, accountService, s.Application, testtoken.TokenManager)
}

func (s *TestUserInfoREST) newUserinfoController(identity *account.Identity, user *account.User) *UserinfoController {
	dummyAccountService := DummyAccountService{
		userinfoStrategy: s.userinfoStrategy,
	}
	return NewUserinfoController(goa.New("auth-test"), dummyAccountService, newGormTestBase(identity, user), testtoken.TokenManager)
}

func newTestAccountProvider(db application.DB) *userprofile.AccountProvider {
	return userprofile.NewAccountProvider(db.Identities(), db.Users(), testtoken.TokenManager, db)
}

func (s *TestUserInfoREST) TestShowUserInfoOK() {

	t := s.T()
	usr, ident, _ := getTestUserAndIdentity()
	userinfoCtrl := s.newUserinfoController(ident, usr)

	_, userInfo := test.ShowUserinfoOK(t, context.Background(), nil, userinfoCtrl)

	require.Equal(t, *userInfo.Email, usr.Email)
	require.Equal(t, *userInfo.PreferredUsername, ident.Username)
	require.Equal(t, *userInfo.Sub, ident.ID.String())
	fullName := strings.Split(usr.FullName, " ")
	require.Equal(t, *userInfo.GivenName, fullName[0])
	require.Equal(t, *userInfo.FamilyName, fullName[1])
}

func (s *TestUserInfoREST) TestShowUserInfoFailsWithInvalidToken() {
	t := s.T()
	svc, ctrl := s.UnSecuredController()

	// Creates an unsigned Token without subject
	jwtToken := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, jwtgo.MapClaims{
		"given_name":         "someGivenName",
		"family_name":        "someFamilyName",
		"preferred_username": "someUserName",
		"email":              "someEmail",
	})
	ctx := jwt.WithJWT(svc.Context, jwtToken)

	_, err := test.ShowUserinfoUnauthorized(t, ctx, svc, ctrl)
	require.Equal(t, err.Errors[0].Detail, fmt.Sprintf("bad token"))

	// We are adding subject, but subject is not matching any of the identities that we have
	sub := uuid.NewV4().String()
	jwtToken.Claims.(jwtgo.MapClaims)["sub"] = sub
	_, err = test.ShowUserinfoUnauthorized(t, ctx, svc, ctrl)
	require.Equal(t, err.Errors[0].Detail, fmt.Sprintf("auth token contains id %s of unknown Identity\n", sub))
}

package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	uuid "github.com/satori/go.uuid"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/suite"
)

type TestAuthorizeREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunAuthorizeREST(t *testing.T) {
	suite.Run(t, &TestAuthorizeREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestAuthorizeREST) UnSecuredController() (*goa.Service, *AuthorizeController) {
	svc := testsupport.ServiceAsUser("Login-Service", testsupport.TestIdentity)
	loginService := newTestKeycloakOAuthProvider(rest.Application)
	return svc, &AuthorizeController{Controller: svc.NewController("AuthorizeController"), Auth: loginService, Configuration: rest.Configuration}
}

func (rest *TestAuthorizeREST) TestAuthorizeOK() {
	t := rest.T()
	svc, ctrl := rest.UnSecuredController()

	redirect := "https://openshift.io"
	clientID := "5dec5fdb-09e3-4453-b73f-5c828832b28e"
	responseType := "code"
	state := uuid.NewV4()

	test.AuthorizeAuthorizeTemporaryRedirect(t, svc.Context, svc, ctrl, nil, &clientID, nil, &redirect, &responseType, nil, state)
}

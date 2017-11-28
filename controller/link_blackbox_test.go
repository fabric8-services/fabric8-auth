package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/suite"
)

type TestLinkREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunLinkREST(t *testing.T) {
	suite.Run(t, &TestLinkREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestLinkREST) UnSecuredController() (*goa.Service, *LinkController) {
	svc := testsupport.ServiceAsUser("Link-Service", testsupport.TestIdentity)
	loginService := newTestKeycloakOAuthProvider(rest.Application)
	return svc, &LinkController{Controller: svc.NewController("login"), Auth: loginService, Configuration: rest.Configuration}
}

func (rest *TestLinkREST) TestLinkSessionRedirects() {
	t := rest.T()
	svc, ctrl := rest.UnSecuredController()

	redirect := "https://openshift.io"
	provider := "github"
	sessionState := uuid.NewV4().String()
	test.SessionLinkTemporaryRedirect(t, svc.Context, svc, ctrl, &provider, &redirect, &sessionState)
}

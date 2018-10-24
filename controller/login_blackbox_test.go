package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestLoginREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunLoginREST(t *testing.T) {
	suite.Run(t, &TestLoginREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestLoginREST) UnSecuredController() (*goa.Service, *LoginController) {
	svc := testsupport.ServiceAsUser("Login-Service", testsupport.TestIdentity)
	return svc, &LoginController{Controller: svc.NewController("login")}
}

func (rest *TestLoginREST) TestLoginOK() {
	t := rest.T()
	svc, ctrl := rest.UnSecuredController()

	redirect := "https://openshift.io"
	test.LoginLoginTemporaryRedirect(t, svc.Context, svc, ctrl, nil, &redirect, nil)
}

func (rest *TestLoginREST) TestOfflineAccessOK() {
	t := rest.T()
	svc, ctrl := rest.UnSecuredController()

	offline := "offline_access"
	redirect := "https://openshift.io"
	resp := test.LoginLoginTemporaryRedirect(t, svc.Context, svc, ctrl, nil, &redirect, &offline)
	assert.Contains(t, resp.Header().Get("Location"), "scope=offline_access")

	resp = test.LoginLoginTemporaryRedirect(t, svc.Context, svc, ctrl, nil, &redirect, nil)
	assert.NotContains(t, resp.Header().Get("Location"), "scope=offline_access")
}

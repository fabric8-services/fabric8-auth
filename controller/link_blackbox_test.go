package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	almtoken "github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestLinkREST struct {
	gormtestsupport.DBTestSuite

	db    *gormapplication.GormDB
	clean func()
}

func TestRunLinkREST(t *testing.T) {
	suite.Run(t, &TestLinkREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestLinkREST) SetupTest() {
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.clean = cleaner.DeleteCreatedEntities(rest.DB)
}

func (rest *TestLinkREST) TearDownTest() {
	rest.clean()
}

func (rest *TestLinkREST) UnSecuredController() (*goa.Service, *LinkController) {
	priv, _ := almtoken.ParsePrivateKey([]byte(almtoken.RSAPrivateKey))

	svc := testsupport.ServiceAsUser("Link-Service", almtoken.NewManagerWithPrivateKey(priv), testsupport.TestIdentity)
	return svc, &LinkController{Controller: svc.NewController("login"), Auth: TestLoginService{}, Configuration: rest.Configuration}
}

func (rest *TestLinkREST) SecuredController() (*goa.Service, *LinkController) {
	priv, _ := almtoken.ParsePrivateKey([]byte(almtoken.RSAPrivateKey))

	loginService := newTestKeycloakOAuthProvider(rest.db, rest.Configuration)

	svc := testsupport.ServiceAsUser("Login-Service", almtoken.NewManagerWithPrivateKey(priv), testsupport.TestIdentity)
	return svc, NewLinkController(svc, loginService, loginService.TokenManager, rest.Configuration)
}

func (rest *TestLinkREST) TestLinkIdPWithoutTokenFails() {
	t := rest.T()
	resource.Require(t, resource.UnitTest)
	service, controller := rest.SecuredController()

	resp, err := test.LinkLinkUnauthorized(t, service.Context, service, controller, nil, nil)
	assert.NotNil(t, err)
	assert.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
}

func (rest *TestLinkREST) TestLinkIdPWithTokenRedirects() {
	t := rest.T()
	resource.Require(t, resource.UnitTest)
	svc, ctrl := rest.UnSecuredController()

	test.LinkLinkTemporaryRedirect(t, svc.Context, svc, ctrl, nil, nil)
}

package controller_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/gormsupport/cleaner"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestTokenREST struct {
	gormtestsupport.DBTestSuite
	identityRepository *MockIdentityRepository

	db    *gormapplication.GormDB
	clean func()
}

func TestRunTokenREST(t *testing.T) {
	suite.Run(t, &TestTokenREST{DBTestSuite: gormtestsupport.NewDBTestSuite("../config.yaml")})
}

func (rest *TestTokenREST) SetupTest() {
	rest.db = gormapplication.NewGormDB(rest.DB)
	rest.clean = cleaner.DeleteCreatedEntities(rest.DB)
}

func (rest *TestTokenREST) TearDownTest() {
	rest.clean()
}

func (rest *TestTokenREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	return svc, &TokenController{Controller: svc.NewController("token"), Auth: TestLoginService{}, Configuration: rest.Configuration}
}

func (rest *TestTokenREST) SecuredController() (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(rest.db, rest.Configuration)

	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	return svc, NewTokenController(svc, loginService, loginService.TokenManager, rest.Configuration, rest.identityRepository)
}

func (rest *TestTokenREST) TestTestUserTokenObtainedFromKeycloakOK() {
	t := rest.T()
	resource.Require(t, resource.UnitTest)
	service, controller := rest.SecuredController()
	resp, result := test.GenerateTokenOK(t, service.Context, service, controller)

	assert.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
	assert.Len(t, result, 2, "The size of token array is not 2")
	for _, data := range result {
		validateToken(t, data, controller)
	}
}

func (rest *TestTokenREST) TestRefreshTokenUsingValidRefreshTokenOK() {
	t := rest.T()
	resource.Require(t, resource.UnitTest)
	service, controller := rest.SecuredController()
	_, result := test.GenerateTokenOK(t, service.Context, service, controller)
	if len(result) != 2 || result[0].Token.RefreshToken == nil {
		t.Fatal("Can't get the test user token")
	}
	refreshToken := result[0].Token.RefreshToken

	payload := &app.RefreshToken{RefreshToken: refreshToken}
	resp, newToken := test.RefreshTokenOK(t, service.Context, service, controller, payload)

	assert.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
	validateToken(t, newToken, controller)
}

func (rest *TestTokenREST) TestRefreshTokenUsingNilTokenFails() {
	t := rest.T()
	resource.Require(t, resource.UnitTest)
	service, controller := rest.SecuredController()

	payload := &app.RefreshToken{}
	_, err := test.RefreshTokenBadRequest(t, service.Context, service, controller, payload)
	assert.NotNil(t, err)
}

func (rest *TestTokenREST) TestRefreshTokenUsingInvalidTokenFails() {
	t := rest.T()
	resource.Require(t, resource.UnitTest)
	service, controller := rest.SecuredController()

	refreshToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.S-vR8LZTQ92iqGCR3rNUG0MiGx2N5EBVq0frCHP_bJ8"
	payload := &app.RefreshToken{RefreshToken: &refreshToken}
	_, err := test.RefreshTokenBadRequest(t, service.Context, service, controller, payload)
	assert.NotNil(t, err)
}

func validateToken(t *testing.T, token *app.AuthToken, controler *TokenController) {
	assert.NotNil(t, token, "Token data is nil")
	assert.NotEmpty(t, token.Token.AccessToken, "Access token is empty")
	assert.NotEmpty(t, token.Token.RefreshToken, "Refresh token is empty")
	assert.NotEmpty(t, token.Token.TokenType, "Token type is empty")
	assert.NotNil(t, token.Token.ExpiresIn, "Expires-in is nil")
	assert.NotNil(t, token.Token.RefreshExpiresIn, "Refresh-expires-in is nil")
	assert.NotNil(t, token.Token.NotBeforePolicy, "Not-before-policy is nil")
}

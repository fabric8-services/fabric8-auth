package controller_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	resource "github.com/fabric8-services/fabric8-auth/authorization/resource/repository"
	resourcetype "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/repository"
	scope "github.com/fabric8-services/fabric8-auth/authorization/resourcetype/scope/repository"
	identityrole "github.com/fabric8-services/fabric8-auth/authorization/role/identityrole/repository"
	role "github.com/fabric8-services/fabric8-auth/authorization/role/repository"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/space"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenRemoteREST struct {
	testsuite.RemoteTestSuite
}

func TestRunTokenRemoteREST(t *testing.T) {
	suite.Run(t, &TestTokenRemoteREST{RemoteTestSuite: testsuite.NewRemoteTestSuite()})
}

func (rest *TestTokenRemoteREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := goa.New("Token-Service")
	manager, err := token.NewManager(rest.Config)
	require.Nil(rest.T(), err)
	return svc, NewTokenController(svc, &MockDBApp{}, nil, nil, nil, manager, nil, rest.Config)
}

func (rest *TestTokenRemoteREST) UnSecuredControllerWithDummyDB() (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(&MockDBApp{})

	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	return svc, NewTokenController(svc, nil, loginService, nil, nil, loginService.TokenManager, newMockKeycloakExternalTokenServiceClient(), rest.Config)
}

func (rest *TestTokenRemoteREST) TestTestUserTokenObtainedFromKeycloakOK() {
	t := rest.T()
	service, controller := rest.UnSecuredControllerWithDummyDB()
	resp, result := test.GenerateTokenOK(t, service.Context, service, controller)

	require.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
	require.Len(t, result, 2, "The size of token array is not 2")
	for _, data := range result {
		validateToken(t, data)
	}
}

func (rest *TestTokenRemoteREST) TestRefreshTokenUsingValidRefreshTokenOK() {
	t := rest.T()
	service, controller := rest.UnSecuredControllerWithDummyDB()
	_, result := test.GenerateTokenOK(t, service.Context, service, controller)
	if len(result) != 2 || result[0].Token.RefreshToken == nil {
		t.Fatal("Can't get the test user token")
	}
	refreshToken := result[0].Token.RefreshToken

	payload := &app.RefreshToken{RefreshToken: refreshToken}
	resp, newToken := test.RefreshTokenOK(t, service.Context, service, controller, payload)

	require.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
	validateToken(t, newToken)
}

func (rest *TestTokenRemoteREST) TestRefreshTokenUsingInvalidTokenFails() {
	t := rest.T()
	service, controller := rest.UnSecuredControllerWithDummyDB()

	refreshToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.S-vR8LZTQ92iqGCR3rNUG0MiGx2N5EBVq0frCHP_bJ8"
	payload := &app.RefreshToken{RefreshToken: &refreshToken}
	_, err := test.RefreshTokenUnauthorized(t, service.Context, service, controller, payload)
	require.NotNil(t, err)
}

func validateToken(t *testing.T, token *app.AuthToken) {
	assert.NotNil(t, token, "Token data is nil")
	assert.NotEmpty(t, token.Token.AccessToken, "Access token is empty")
	assert.NotEmpty(t, token.Token.RefreshToken, "Refresh token is empty")
	assert.NotEmpty(t, token.Token.TokenType, "Token type is empty")
	assert.NotNil(t, token.Token.ExpiresIn, "Expires-in is nil")
	assert.NotNil(t, token.Token.RefreshExpiresIn, "Refresh-expires-in is nil")
	assert.NotNil(t, token.Token.NotBeforePolicy, "Not-before-policy is nil")
}

type MockDBApp struct {
}

func (m *MockDBApp) Identities() account.IdentityRepository                         { return &MockIdentityRepository{} }
func (m *MockDBApp) SpaceResources() space.ResourceRepository                       { return nil }
func (m *MockDBApp) Users() account.UserRepository                                  { return nil }
func (m *MockDBApp) OauthStates() auth.OauthStateReferenceRepository                { return nil }
func (m *MockDBApp) ExternalTokens() provider.ExternalTokenRepository               { return nil }
func (m *MockDBApp) VerificationCodes() account.VerificationCodeRepository          { return nil }
func (m *MockDBApp) ResourceRepository() resource.ResourceRepository                { return nil }
func (m *MockDBApp) ResourceTypeRepository() resourcetype.ResourceTypeRepository    { return nil }
func (m *MockDBApp) ResourceTypeScopeRepository() scope.ResourceTypeScopeRepository { return nil }
func (m *MockDBApp) IdentityRoleRepository() identityrole.IdentityRoleRepository    { return nil }
func (m *MockDBApp) RoleRepository() role.RoleRepository                            { return nil }

func (m *MockDBApp) BeginTransaction() (application.Transaction, error) {
	return &MockDBApp{}, nil
}

func (m *MockDBApp) Commit() error   { return nil }
func (m *MockDBApp) Rollback() error { return nil }

type MockIdentityRepository struct {
}

func (m *MockIdentityRepository) CheckExists(ctx context.Context, id string) error { return nil }
func (m *MockIdentityRepository) Load(ctx context.Context, id uuid.UUID) (*account.Identity, error) {
	return nil, errors.NotFoundError{}
}
func (m *MockIdentityRepository) LoadWithUser(ctx context.Context, id uuid.UUID) (*account.Identity, error) {
	return nil, errors.NotFoundError{}
}
func (m *MockIdentityRepository) Create(ctx context.Context, identity *account.Identity) error {
	return nil
}
func (m *MockIdentityRepository) Lookup(ctx context.Context, username, profileURL, providerType string) (*account.Identity, error) {
	return nil, errors.NotFoundError{}
}
func (m *MockIdentityRepository) Save(ctx context.Context, identity *account.Identity) error {
	return nil
}
func (m *MockIdentityRepository) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *MockIdentityRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]account.Identity, error) {
	return nil, nil
}
func (m *MockIdentityRepository) List(ctx context.Context) ([]account.Identity, error) {
	return nil, nil
}
func (m *MockIdentityRepository) IsValid(context.Context, uuid.UUID) bool { return true }
func (m *MockIdentityRepository) Search(ctx context.Context, q string, start int, limit int) ([]account.Identity, int, error) {
	return nil, 1, nil
}

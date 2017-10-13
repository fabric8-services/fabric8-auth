package controller_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/configuration"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	"github.com/fabric8-services/fabric8-auth/token"

	"path/filepath"

	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestTokenRemoteREST struct {
	suite.Suite
	config  *configuration.ConfigurationData
	testDir string
}

func TestRunTokenRemoteREST(t *testing.T) {
	resource.Require(t, resource.Remote)
	config, err := configuration.GetConfigurationData()
	if err != nil {
		t.Fatalf("Failed to setup the Configuration: %s", err.Error())
	}
	suite.Run(t, &TestTokenRemoteREST{config: config})
}

func (rest *TestTokenRemoteREST) SetupTest() {
	rest.testDir = filepath.Join("test-files", "token")
}

func (rest *TestTokenRemoteREST) TearDownTest() {
}

func (rest *TestTokenRemoteREST) UnSecuredController() (*goa.Service, *TokenController) {
	svc := goa.New("Token-Service")
	manager, err := token.NewManager(rest.config)
	require.Nil(rest.T(), err)
	return svc, NewTokenController(svc, nil, nil, manager, rest.config, nil)
}

func (rest *TestTokenRemoteREST) UnSecuredControllerWithDummyDB() (*goa.Service, *TokenController) {
	loginService := newTestKeycloakOAuthProvider(&gormapplication.GormDB{}, rest.config)

	svc := testsupport.ServiceAsUser("Token-Service", testsupport.TestIdentity)
	repo := &MockIdentityRepository{&testsupport.TestIdentity}
	return svc, NewTokenController(svc, loginService, nil, loginService.TokenManager, rest.config, repo)
}

func (rest *TestTokenRemoteREST) TestPublicKeys() {
	svc, ctrl := rest.UnSecuredController()

	rest.T().Run("file not found", func(t *testing.T) {
		_, keys := test.KeysTokenOK(rest.T(), svc.Context, svc, ctrl, nil)
		rest.checkJWK(keys)
	})
	rest.T().Run("file not found", func(t *testing.T) {
		jwk := "jwk"
		_, keys := test.KeysTokenOK(rest.T(), svc.Context, svc, ctrl, &jwk)
		rest.checkJWK(keys)
	})
	rest.T().Run("file not found", func(t *testing.T) {
		pem := "pem"
		_, keys := test.KeysTokenOK(rest.T(), svc.Context, svc, ctrl, &pem)
		rest.checkPEM(keys)
	})
}

func (rest *TestTokenRemoteREST) TestTestUserTokenObtainedFromKeycloakOK() {
	t := rest.T()
	service, controller := rest.UnSecuredControllerWithDummyDB()
	resp, result := test.GenerateTokenOK(t, service.Context, service, controller)

	require.Equal(t, resp.Header().Get("Cache-Control"), "no-cache")
	require.Len(t, result, 2, "The size of token array is not 2")
	for _, data := range result {
		validateToken(t, data, controller)
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
	validateToken(t, newToken, controller)
}

func (rest *TestTokenRemoteREST) TestRefreshTokenUsingInvalidTokenFails() {
	t := rest.T()
	service, controller := rest.UnSecuredControllerWithDummyDB()

	refreshToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.S-vR8LZTQ92iqGCR3rNUG0MiGx2N5EBVq0frCHP_bJ8"
	payload := &app.RefreshToken{RefreshToken: &refreshToken}
	_, err := test.RefreshTokenUnauthorized(t, service.Context, service, controller, payload)
	require.NotNil(t, err)
}

func (rest *TestTokenRemoteREST) checkPEM(keys *app.PublicKeys) {
	compareWithGolden(rest.T(), filepath.Join(rest.testDir, "keys", "ok_pem.golden.json"), keys)
}

func (rest *TestTokenRemoteREST) checkJWK(keys *app.PublicKeys) {
	compareWithGolden(rest.T(), filepath.Join(rest.testDir, "keys", "ok_jwk.golden.json"), keys)
}

/* MockUserRepositoryService */

type MockIdentityRepository struct {
	testIdentity *account.Identity
}

// Load returns a single Identity as a Database Model
// This is more for use internally, and probably not what you want in  your controllers
func (m *MockIdentityRepository) Load(ctx context.Context, id uuid.UUID) (*account.Identity, error) {
	return m.testIdentity, nil
}

// Exists returns true|false whether an identity exists with a specific identifier
func (m *MockIdentityRepository) Exists(ctx context.Context, id string) (bool, error) {
	return true, nil
}

// Create creates a new record.
func (m *MockIdentityRepository) Create(ctx context.Context, model *account.Identity) error {
	return nil
}

// Lookup looks for an existing identity with the given `profileURL` or creates a new one
func (m *MockIdentityRepository) Lookup(ctx context.Context, username, profileURL, providerType string) (*account.Identity, error) {
	return m.testIdentity, nil
}

// Save modifies a single record.
func (m *MockIdentityRepository) Save(ctx context.Context, model *account.Identity) error {
	m.testIdentity = model
	return nil
}

// Delete removes a single record.
func (m *MockIdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return nil
}

// Query expose an open ended Query model
func (m *MockIdentityRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]account.Identity, error) {
	var identities []account.Identity
	identities = append(identities, *m.testIdentity)
	return identities, nil
}

// First returns the first Identity element that matches the given criteria
func (m *MockIdentityRepository) First(funcs ...func(*gorm.DB) *gorm.DB) (*account.Identity, error) {
	return m.testIdentity, nil
}

func (m *MockIdentityRepository) List(ctx context.Context) ([]account.Identity, error) {
	var rows []account.Identity
	rows = append(rows, *m.testIdentity)
	return rows, nil
}

func (m *MockIdentityRepository) CheckExists(ctx context.Context, id string) error {
	return nil
}

func (m *MockIdentityRepository) IsValid(ctx context.Context, id uuid.UUID) bool {
	return true
}

func (m *MockIdentityRepository) Search(ctx context.Context, q string, start int, limit int) ([]account.Identity, int, error) {
	result := []account.Identity{}
	result = append(result, *m.testIdentity)
	return result, 1, nil
}

package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/login"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

/*  For recent spaces test */

type TestRecentSpacesREST struct {
	gormtestsupport.RemoteTestSuite
	configuration      *configuration.ConfigurationData
	identityRepository *MockIdentityRepository
	userRepository     *MockUserRepository

	clean func()
}

func TestRunRecentSpacesREST(t *testing.T) {
	suite.Run(t, &TestRecentSpacesREST{RemoteTestSuite: gormtestsupport.NewRemoteTestSuite("../config.yaml")})
}

func (rest *TestRecentSpacesREST) newTestKeycloakOAuthProvider(db application.DB) *login.KeycloakOAuthProvider {
	return login.NewKeycloakOAuthProvider(rest.identityRepository, rest.userRepository, testtoken.TokenManager, db)
}

func (rest *TestRecentSpacesREST) SetupTest() {
	c, err := configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
	rest.configuration = c
	require.Nil(rest.T(), err)

	identity := account.Identity{}
	user := account.User{}
	identity.User = user

	rest.identityRepository = &MockIdentityRepository{testIdentity: &identity}
	rest.userRepository = &MockUserRepository{}
}

/* MockUserRepositoryService */

type MockIdentityRepository struct {
	testIdentity *account.Identity
}

func (rest *TestRecentSpacesREST) SecuredController() (*goa.Service, *TokenController) {
	svc := testsupport.ServiceAsUser("Login-Service", testsupport.TestIdentity)
	tokenController := &TokenController{
		Controller:         svc.NewController("login"),
		TokenManager:       testtoken.TokenManager,
		Configuration:      rest.configuration,
		identityRepository: rest.identityRepository,
	}
	return svc, tokenController
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

type MockUserRepository struct {
	User *account.User
}

func (m MockUserRepository) Load(ctx context.Context, id uuid.UUID) (*account.User, error) {
	if m.User == nil {
		return nil, errors.New("not found")
	}
	return m.User, nil
}

func (m MockUserRepository) Exists(ctx context.Context, id string) (bool, error) {
	if m.User == nil {
		return false, errors.New("not found")
	}
	return true, nil
}

// Create creates a new record.
func (m MockUserRepository) Create(ctx context.Context, u *account.User) error {
	m.User = u
	return nil
}

// Save modifies a single record
func (m MockUserRepository) Save(ctx context.Context, model *account.User) error {
	return m.Create(ctx, model)
}

// Save modifies a single record
func (m MockUserRepository) CheckExists(ctx context.Context, id string) error {
	return nil
}

// Delete removes a single record.
func (m MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	m.User = nil
	return nil
}

// List return all users
func (m MockUserRepository) List(ctx context.Context) ([]account.User, error) {
	return []account.User{*m.User}, nil
}

// Query expose an open ended Query model
func (m MockUserRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]account.User, error) {
	return []account.User{*m.User}, nil
}

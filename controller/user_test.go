package controller_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	res "github.com/fabric8-services/fabric8-auth/authorization/resource"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/space"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token/provider"

	token "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestUserREST struct {
	gormtestsupport.DBTestSuite
}

func TestRunUserREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestUserREST{})
}

func (rest *TestUserREST) SetupSuite() {
	rest.DBTestSuite.SetupSuite()

}

func (rest *TestUserREST) newUserController(identity *account.Identity, user *account.User) *UserController {
	return NewUserController(goa.New("wit-test"), newGormTestBase(identity, user), testtoken.TokenManager, rest.Configuration)
}

func (rest *TestUserREST) TestCurrentAuthorizedMissingUUID() {
	resource.Require(rest.T(), resource.UnitTest)
	jwtToken := token.New(token.SigningMethodRS256)
	ctx := jwt.WithJWT(context.Background(), jwtToken)

	userCtrl := rest.newUserController(nil, nil)
	test.ShowUserBadRequest(rest.T(), ctx, nil, userCtrl, nil, nil)
}

func (rest *TestUserREST) TestCurrentAuthorizedNonUUID() {
	// given
	jwtToken := token.New(token.SigningMethodRS256)
	jwtToken.Claims.(token.MapClaims)["sub"] = "aa"
	ctx := jwt.WithJWT(context.Background(), jwtToken)
	// when
	userCtrl := rest.newUserController(nil, nil)
	// then
	test.ShowUserBadRequest(rest.T(), ctx, nil, userCtrl, nil, nil)
}

func (rest *TestUserREST) TestCurrentAuthorizedMissingIdentity() {
	// given
	jwtToken := token.New(token.SigningMethodRS256)
	jwtToken.Claims.(token.MapClaims)["sub"] = uuid.NewV4().String()
	ctx := jwt.WithJWT(context.Background(), jwtToken)
	// when
	userCtrl := rest.newUserController(nil, nil)
	// then
	test.ShowUserUnauthorized(rest.T(), ctx, nil, userCtrl, nil, nil)
}

func (rest *TestUserREST) TestCurrentAuthorizedOK() {
	// given
	ctx, userCtrl, usr, ident := rest.initTestCurrentAuthorized()
	// when
	res, user := test.ShowUserOK(rest.T(), ctx, nil, userCtrl, nil, nil)
	// then
	rest.assertCurrentUser(*user, ident, usr)
	rest.assertResponseHeaders(res, usr)
}

func (rest *TestUserREST) TestCurrentAuthorizedOKUsingExpiredIfModifiedSinceHeader() {
	// given
	ctx, userCtrl, usr, ident := rest.initTestCurrentAuthorized()
	// when
	ifModifiedSince := usr.UpdatedAt.Add(-1 * time.Hour).UTC().Format(http.TimeFormat)
	res, user := test.ShowUserOK(rest.T(), ctx, nil, userCtrl, &ifModifiedSince, nil)
	// then
	rest.assertCurrentUser(*user, ident, usr)
	rest.assertResponseHeaders(res, usr)
}

func (rest *TestUserREST) TestCurrentAuthorizedOKUsingExpiredIfNoneMatchHeader() {
	// given
	ctx, userCtrl, usr, ident := rest.initTestCurrentAuthorized()
	// when
	ifNoneMatch := "foo"
	res, user := test.ShowUserOK(rest.T(), ctx, nil, userCtrl, nil, &ifNoneMatch)
	// then
	rest.assertCurrentUser(*user, ident, usr)
	rest.assertResponseHeaders(res, usr)
}

func (rest *TestUserREST) TestCurrentAuthorizedNotModifiedUsingIfModifiedSinceHeader() {
	// given
	ctx, userCtrl, usr, _ := rest.initTestCurrentAuthorized()
	// when
	ifModifiedSince := app.ToHTTPTime(usr.UpdatedAt)
	res := test.ShowUserNotModified(rest.T(), ctx, nil, userCtrl, &ifModifiedSince, nil)
	// then
	rest.assertResponseHeaders(res, usr)
}

func (rest *TestUserREST) TestCurrentAuthorizedNotModifiedUsingIfNoneMatchHeader() {
	// given
	ctx, userCtrl, usr, _ := rest.initTestCurrentAuthorized()
	// when
	ifNoneMatch := app.GenerateEntityTag(usr)
	res := test.ShowUserNotModified(rest.T(), ctx, nil, userCtrl, nil, &ifNoneMatch)
	// then
	rest.assertResponseHeaders(res, usr)
}

func (rest *TestUserREST) TestPrivateEmailVisibleIfNotPrivate() {
	ctx, userCtrl, usr, _ := rest.initTestCurrentAuthorized()
	usr.EmailPrivate = false
	_, err := testsupport.CreateTestUser(rest.DB, &usr)
	require.NoError(rest.T(), err)
	_, returnedUser := test.ShowUserOK(rest.T(), ctx, nil, userCtrl, nil, nil)
	require.NotNil(rest.T(), returnedUser)
	require.Equal(rest.T(), usr.Email, *returnedUser.Data.Attributes.Email)
}

func (rest *TestUserREST) TestPrivateEmailVisibleIfPrivate() {
	ctx, userCtrl, usr, _ := rest.initTestCurrentAuthorized()
	usr.EmailPrivate = true
	_, err := testsupport.CreateTestUser(rest.DB, &usr)
	require.NoError(rest.T(), err)
	_, returnedUser := test.ShowUserOK(rest.T(), ctx, nil, userCtrl, nil, nil)
	require.NotNil(rest.T(), returnedUser)
	require.NotEqual(rest.T(), "", *returnedUser.Data.Attributes.Email)
	require.Equal(rest.T(), usr.Email, *returnedUser.Data.Attributes.Email)
}

func (rest *TestUserREST) initTestCurrentAuthorized() (context.Context, app.UserController, account.User, account.Identity) {
	jwtToken := token.New(token.SigningMethodRS256)
	jwtToken.Claims.(token.MapClaims)["sub"] = uuid.NewV4().String()
	ctx := jwt.WithJWT(context.Background(), jwtToken)
	usr := account.User{
		ID: uuid.NewV4(),
		Lifecycle: gormsupport.Lifecycle{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		FullName: "TestCurrentAuthorizedOK User",
		ImageURL: "someURL",
		Cluster:  "cluster",
		Email:    uuid.NewV4().String() + "email@domain.com",
	}
	ident := account.Identity{ID: uuid.NewV4(), Username: "TestUser", ProviderType: account.KeycloakIDP, User: usr, UserID: account.NullUUID{UUID: usr.ID, Valid: true}}
	userCtrl := rest.newUserController(&ident, &usr)
	return ctx, userCtrl, usr, ident
}

func (rest *TestUserREST) assertCurrentUser(user app.User, ident account.Identity, usr account.User) {
	require.NotNil(rest.T(), user)
	require.NotNil(rest.T(), user.Data)
	require.NotNil(rest.T(), user.Data.Attributes)
	assert.Equal(rest.T(), usr.FullName, *user.Data.Attributes.FullName)
	assert.Equal(rest.T(), ident.Username, *user.Data.Attributes.Username)
	assert.Equal(rest.T(), usr.ImageURL, *user.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), usr.Email, *user.Data.Attributes.Email)
	assert.Equal(rest.T(), ident.ProviderType, *user.Data.Attributes.ProviderType)
}

func (rest *TestUserREST) assertResponseHeaders(res http.ResponseWriter, usr account.User) {
	require.NotNil(rest.T(), res.Header()[app.LastModified])
	assert.Equal(rest.T(), usr.UpdatedAt.Truncate(time.Second).UTC().Format(http.TimeFormat), res.Header()[app.LastModified][0])
	require.NotNil(rest.T(), res.Header()[app.CacheControl])
	assert.Equal(rest.T(), rest.Configuration.GetCacheControlUser(), res.Header()[app.CacheControl][0])
	require.NotNil(rest.T(), res.Header()[app.ETag])
	assert.Equal(rest.T(), app.GenerateEntityTag(usr), res.Header()[app.ETag][0])

}

type TestIdentityRepository struct {
	Identity *account.Identity
}

// Load returns a single Identity as a Database Model
func (m TestIdentityRepository) Load(ctx context.Context, id uuid.UUID) (*account.Identity, error) {
	if m.Identity == nil {
		return nil, errors.New("not found")
	}
	return m.Identity, nil
}

// CheckExists returns nil if the given ID exists otherwise returns an error
func (m TestIdentityRepository) CheckExists(ctx context.Context, id string) error {
	if m.Identity == nil {
		return errors.New("not found")
	}
	return nil
}

// Create creates a new record.
func (m TestIdentityRepository) Create(ctx context.Context, model *account.Identity) error {
	m.Identity = model
	return nil
}

// Lookup looks up a record or creates a new one.
func (m TestIdentityRepository) Lookup(ctx context.Context, username, profileURL, providerType string) (*account.Identity, error) {
	return nil, nil
}

// Lookup looks up a record or creates a new one.
func (m TestIdentityRepository) Search(ctx context.Context, q string, start int, limit int) ([]account.Identity, int, error) {
	return nil, 0, nil
}

// Save modifies a single record.
func (m TestIdentityRepository) Save(ctx context.Context, model *account.Identity) error {
	return m.Create(ctx, model)
}

// Delete removes a single record.
func (m TestIdentityRepository) Delete(ctx context.Context, id uuid.UUID) error {
	m.Identity = nil
	return nil
}

// Query expose an open ended Query model
func (m TestIdentityRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]account.Identity, error) {
	return []account.Identity{*m.Identity}, nil
}

func (m TestIdentityRepository) List(ctx context.Context) ([]account.Identity, error) {
	rows := []account.Identity{*m.Identity}
	return rows, nil
}

func (m TestIdentityRepository) IsValid(ctx context.Context, id uuid.UUID) bool {
	return true
}

type TestUserRepository struct {
	User *account.User
}

func (m TestUserRepository) Load(ctx context.Context, id uuid.UUID) (*account.User, error) {
	if m.User == nil {
		return nil, errors.New("not found")
	}
	return m.User, nil
}

func (m TestUserRepository) CheckExists(ctx context.Context, id string) error {
	if m.User == nil {
		return errors.New("not found")
	}
	return nil
}

// Create creates a new record.
func (m TestUserRepository) Create(ctx context.Context, u *account.User) error {
	m.User = u
	return nil
}

// Save modifies a single record
func (m TestUserRepository) Save(ctx context.Context, model *account.User) error {
	return m.Create(ctx, model)
}

// Delete removes a single record.
func (m TestUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	m.User = nil
	return nil
}

// List return all users
func (m TestUserRepository) List(ctx context.Context) ([]account.User, error) {
	return []account.User{*m.User}, nil
}

// Query expose an open ended Query model
func (m TestUserRepository) Query(funcs ...func(*gorm.DB) *gorm.DB) ([]account.User, error) {
	return []account.User{*m.User}, nil
}

type GormTestBase struct {
	IdentityRepository account.IdentityRepository
	UserRepository     account.UserRepository
}

// Identities creates new Identity repository
func (g *GormTestBase) Identities() account.IdentityRepository {
	return g.IdentityRepository
}

// Users creates new user repository
func (g *GormTestBase) Users() account.UserRepository {
	return g.UserRepository
}

func (g *GormTestBase) OauthStates() auth.OauthStateReferenceRepository {
	return nil
}

func (g *GormTestBase) SpaceResources() space.ResourceRepository {
	return nil
}

func (g *GormTestBase) ExternalTokens() provider.ExternalTokenRepository {
	return nil
}

func (g *GormTestBase) ResourceRepository() res.ResourceRepository {
	return nil
}

func (g *GormTestBase) ResourceTypeRepository() res.ResourceTypeRepository {
	return nil
}

func (g *GormTestBase) DB() *gorm.DB {
	return nil
}

// SetTransactionIsolationLevel sets the isolation level for
// See also https://www.postgresql.org/docs/9.3/static/sql-set-transaction.html
func (g *GormTestBase) SetTransactionIsolationLevel(level interface{}) error {
	return nil
}

func (g *GormTestBase) Commit() error {
	return nil
}

func (g *GormTestBase) Rollback() error {
	return nil
}

// Begin implements TransactionSupport
func (g *GormTestBase) BeginTransaction() (application.Transaction, error) {
	return g, nil
}

func newGormTestBase(identity *account.Identity, user *account.User) *GormTestBase {
	return &GormTestBase{
		IdentityRepository: TestIdentityRepository{Identity: identity},
		UserRepository:     TestUserRepository{User: user}}
}

package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	res "github.com/fabric8-services/fabric8-auth/authorization/resource"
	"github.com/fabric8-services/fabric8-auth/configuration"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/login/link"
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
	config             configuration.ConfigurationData
	svc                *goa.Service
	usersController    *UsersController
	userRepo           account.UserRepository
	identityRepo       account.IdentityRepository
	userProfileService login.UserProfileService
	linkAPIService     link.KeycloakIDPService
}

func TestRunUserREST(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestUserREST{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

func (rest *TestUserREST) SetupSuite() {
	config, err := configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
	rest.config = *config

	rest.DBTestSuite.SetupSuite()
	rest.svc = testsupport.ServiceAsUser("Login-Service", testsupport.TestIdentity) //goa.New("test")
	testAttributeValue := "a"
	dummyProfileResponse := createDummyUserProfileResponse(&testAttributeValue, &testAttributeValue, &testAttributeValue)
	keycloakUserProfileService := newDummyUserProfileService(dummyProfileResponse)
	rest.userProfileService = keycloakUserProfileService
	rest.linkAPIService = &dummyKeycloakLinkService{}
	rest.usersController = NewUsersController(rest.svc, rest.Application, rest.Configuration, rest.userProfileService, rest.linkAPIService)
	rest.userRepo = rest.Application.Users()
	rest.identityRepo = rest.Application.Identities()
}

func (rest *TestUserREST) newUserController(identity *account.Identity, user *account.User) *UserController {
	return NewUserController(goa.New("auth-test"), newGormTestBase(identity, user), testtoken.TokenManager, rest.userProfileService, &rest.config)
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
	assert.Equal(rest.T(), rest.config.GetCacheControlUser(), res.Header()[app.CacheControl][0])
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

func (rest *TestUserREST) createRandomUser(fullname string) account.User {
	user := account.User{
		Email:    uuid.NewV4().String() + "primaryForUpdat7e@example.com",
		FullName: fullname,
		ImageURL: "someURLForUpdate",
		ID:       uuid.NewV4(),
		Company:  uuid.NewV4().String() + "company",
		Cluster:  "My OSO cluster url",
	}

	err := rest.userRepo.Create(context.Background(), &user)
	require.Nil(rest.T(), err)
	return user
}

func (rest *TestUserREST) createRandomIdentity(user account.User, providerType string) account.Identity {
	profile := "foobarforupdate.com/" + uuid.NewV4().String() + "/" + user.ID.String()
	identity := account.Identity{
		Username:     "TestUpdateUserIntegration123" + uuid.NewV4().String(),
		ProviderType: providerType,
		ProfileURL:   &profile,
		User:         user,
		UserID:       account.NullUUID{UUID: user.ID, Valid: true},
	}
	err := rest.identityRepo.Create(context.Background(), &identity)
	require.Nil(rest.T(), err)
	return identity
}

func (rest *TestUserREST) SecuredController(identity account.Identity) (*goa.Service, *UserController) {
	svc := testsupport.ServiceAsUser("User-Service", identity)
	controller := NewUserController(rest.svc, rest.Application, nil, rest.userProfileService, rest.Configuration)
	return svc, controller
}

func createUpdateUserPayloadWithoutContextInformation(email, fullName, bio, imageURL, profileURL *string) *app.UpdateUserPayload {
	return &app.UpdateUserPayload{
		Data: &app.UpdateUserData{
			Type: "identities",
			Attributes: &app.UpdateIdentityDataAttributes{
				Email:    email,
				FullName: fullName,
				Bio:      bio,
				ImageURL: imageURL,
				URL:      profileURL,
			},
		},
	}
}

func createUpdateUserPayload(email, fullName, bio, imageURL, profileURL, company, username *string, registrationCompleted *bool, contextInformation map[string]interface{}) *app.UpdateUserPayload {
	return &app.UpdateUserPayload{
		Data: &app.UpdateUserData{
			Type: "identities",
			Attributes: &app.UpdateIdentityDataAttributes{
				Email:                 email,
				FullName:              fullName,
				Bio:                   bio,
				ImageURL:              imageURL,
				URL:                   profileURL,
				Company:               company,
				ContextInformation:    contextInformation,
				Username:              username,
				RegistrationCompleted: registrationCompleted,
			},
		},
	}
}

func (rest *TestUserREST) TestUpdateUserOK() {
	// Create a user
	user := rest.createRandomUser("TestUpdateUserOK")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)

	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(rest.T(), user.FullName, *result.Data.Attributes.FullName)
	assert.Equal(rest.T(), user.ImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), identity.ProviderType, *result.Data.Attributes.ProviderType)
	assert.Equal(rest.T(), identity.Username, *result.Data.Attributes.Username)
	assert.Equal(rest.T(), user.Company, *result.Data.Attributes.Company)

	// Save user data to which you want to update
	// when
	newEmail := "TestUpdateUserOK-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserOK"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	newCompany := "updateCompany " + uuid.NewV4().String()
	secureService, secureController := rest.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}
	// Update the user
	updateUserPayload := createUpdateUserPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, &newCompany, nil, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)

	// Retrive the user and check if the user has been updated to what you wanted to be
	// then
	require.NotNil(rest.T(), result)
	// let's fetch it and validate
	_, result = test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	require.NotNil(rest.T(), result)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(rest.T(), newFullName, *result.Data.Attributes.FullName)
	assert.Equal(rest.T(), newImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), newBio, *result.Data.Attributes.Bio)
	assert.Equal(rest.T(), newProfileURL, *result.Data.Attributes.URL)
	assert.Equal(rest.T(), newCompany, *result.Data.Attributes.Company)

	updatedContextInformation := result.Data.Attributes.ContextInformation
	assert.Equal(rest.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])

	countValue, ok := updatedContextInformation["count"].(float64)
	assert.True(rest.T(), ok)
	assert.Equal(rest.T(), contextInformation["count"], int(countValue))
	assert.Equal(rest.T(), contextInformation["rate"], updatedContextInformation["rate"])
}

func (rest *TestUserREST) TestUpdateUserNameMulitpleTimesForbidden() {

	user := rest.createRandomUser("OK")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)

	newUserName := identity.Username + uuid.NewV4().String()
	secureService, secureController := rest.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	// you can update username multiple times.
	// also omit registrationCompleted
	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, &newUserName, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)

	boolTrue := true
	updateUserPayload = createUpdateUserPayload(nil, nil, nil, nil, nil, nil, &newUserName, &boolTrue, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)

	// next attempt should fail.
	newUserName = identity.Username + uuid.NewV4().String()
	updateUserPayload = createUpdateUserPayload(nil, nil, nil, nil, nil, nil, &newUserName, nil, contextInformation)
	test.UpdateUserForbidden(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
}

func (rest *TestUserREST) TestUpdateUserNameMulitpleTimesOK() {

	user := rest.createRandomUser("OK")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)

	newUserName := identity.Username // new username = old userame
	secureService, secureController := rest.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, &newUserName, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	require.False(rest.T(), *result.Data.Attributes.RegistrationCompleted)

	// next attempt should PASS.
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	require.False(rest.T(), *result.Data.Attributes.RegistrationCompleted)

}

func (rest *TestUserREST) TestUpdateRegistrationCompletedOK() {
	user := rest.createRandomUser("OK")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)

	secureService, secureController := rest.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	require.False(rest.T(), *result.Data.Attributes.RegistrationCompleted)

	// next attempt should PASS.
	boolTrue := true
	updateUserPayload = createUpdateUserPayload(nil, nil, nil, nil, nil, nil, nil, &boolTrue, contextInformation)
	test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
}

func (rest *TestUserREST) TestUpdateRegistrationCompletedBadRequest() {
	user := rest.createRandomUser("OKRegCompleted")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)

	secureService, secureController := rest.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	require.False(rest.T(), *result.Data.Attributes.RegistrationCompleted)

	// next attempt should fail.
	boolFalse := false
	updateUserPayload = createUpdateUserPayload(nil, nil, nil, nil, nil, nil, nil, &boolFalse, contextInformation)
	test.UpdateUserBadRequest(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)

}

func (rest *TestUserREST) TestUpdateRegistrationCompletedAndUsernameOK() {

	// In this test case, we send both registrationCompleted=True and an updated username
	// as part of HTTP PATCH.

	user := rest.createRandomUser("OKRegCompleted")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)

	secureService, secureController := rest.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	require.False(rest.T(), *result.Data.Attributes.RegistrationCompleted)

	boolTrue := true
	newUserName := identity.Username + uuid.NewV4().String()
	updateUserPayload = createUpdateUserPayload(nil, nil, nil, nil, nil, nil, &newUserName, &boolTrue, contextInformation)
	test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)

}

func (rest *TestUserREST) TestUpdateExistingUsernameForbidden() {
	// create 2 users.
	user := rest.createRandomUser("OK")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)

	user2 := rest.createRandomUser("OK2")
	identity2 := rest.createRandomIdentity(user2, account.KeycloakIDP)
	_, result2 := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity2.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity2.ID.String(), *result2.Data.ID)

	// try updating using the username of an existing ( just created ) user.
	secureService, secureController := rest.SecuredController(identity2)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	newUserName := identity.Username
	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, &newUserName, nil, contextInformation)
	test.UpdateUserBadRequest(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
}

func (rest *TestUserREST) TestUpdateExistingEmailForbidden() {
	// create 2 users.
	user := rest.createRandomUser("OK")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)

	user2 := rest.createRandomUser("OK2")
	identity2 := rest.createRandomIdentity(user2, account.KeycloakIDP)
	_, result2 := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity2.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity2.ID.String(), *result2.Data.ID)

	// try updating using the email of an existing ( just created ) user.
	secureService, secureController := rest.SecuredController(identity2)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	newEmail := user.Email
	updateUserPayload := createUpdateUserPayload(&newEmail, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	test.UpdateUserBadRequest(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
}

func (rest *TestUserREST) TestUpdateUserVariableSpacesInNameOK() {

	// given
	user := rest.createRandomUser("OK")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assertUser(rest.T(), result.Data, user, identity)
	// when
	newEmail := "updated-" + uuid.NewV4().String() + "@email.com"

	// This is the special thing we are testing - everything else
	// has been tested in other tests.
	// We use the full name to derive the first and the last name
	// This test checks that the splitting is done correctly,
	// ie, the first word is the first name ,and the rest is the last name

	newFullName := " This name   has a   lot of spaces   in it"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	newCompany := "updateCompany " + uuid.NewV4().String()

	secureService, secureController := rest.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}
	//secureController, secureService := createSecureController(t, identity)
	updateUserPayload := createUpdateUserPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, &newCompany, nil, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	// then
	require.NotNil(rest.T(), result)
	// let's fetch it and validate
	_, result = test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	require.NotNil(rest.T(), result)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(rest.T(), newFullName, *result.Data.Attributes.FullName)
	assert.Equal(rest.T(), newImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), newBio, *result.Data.Attributes.Bio)
	assert.Equal(rest.T(), newProfileURL, *result.Data.Attributes.URL)
	assert.Equal(rest.T(), newCompany, *result.Data.Attributes.Company)

	updatedContextInformation := result.Data.Attributes.ContextInformation
	assert.Equal(rest.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])
	countValue, ok := updatedContextInformation["count"].(float64)
	assert.True(rest.T(), ok)
	assert.Equal(rest.T(), contextInformation["count"], int(countValue))
	assert.Equal(rest.T(), contextInformation["rate"], updatedContextInformation["rate"])
}

//Test to unset variable in contextInformation

func (rest *TestUserREST) TestUpdateUserUnsetVariableInContextInfo() {
	// given
	user := rest.createRandomUser("TestUpdateUserUnsetVariableInContextInfo")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(rest.T(), user.FullName, *result.Data.Attributes.FullName)
	assert.Equal(rest.T(), user.ImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), identity.ProviderType, *result.Data.Attributes.ProviderType)
	assert.Equal(rest.T(), identity.Username, *result.Data.Attributes.Username)

	// when
	newEmail := "TestUpdateUserUnsetVariableInContextInfo-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserUnsetVariableInContextInfo"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	secureService, secureController := rest.SecuredController(identity)
	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}

	updateUserPayload := createUpdateUserPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, nil, nil, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	// then
	require.NotNil(rest.T(), result)
	// let's fetch it and validate the usual stuff.
	_, result = test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	require.NotNil(rest.T(), result)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(rest.T(), newFullName, *result.Data.Attributes.FullName)
	assert.Equal(rest.T(), newImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), newBio, *result.Data.Attributes.Bio)
	assert.Equal(rest.T(), newProfileURL, *result.Data.Attributes.URL)
	updatedContextInformation := result.Data.Attributes.ContextInformation
	assert.Equal(rest.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])

	// Usual stuff done, now lets unset
	contextInformation = map[string]interface{}{
		"last_visited": nil,
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}

	updateUserPayload = createUpdateUserPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, nil, nil, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	// then
	require.NotNil(rest.T(), result)
	// let's fetch it and validate the usual stuff.
	_, result = test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	require.NotNil(rest.T(), result)
	updatedContextInformation = result.Data.Attributes.ContextInformation

	// what was passed as non-nill should be intact.
	assert.Equal(rest.T(), contextInformation["space"], updatedContextInformation["space"])

	// what was pass as nil should not be found!
	_, ok := updatedContextInformation["last_visited"]
	assert.Equal(rest.T(), false, ok)
}

//Pass no contextInformation and no one complains.
//This is as per general service behaviour.

func (rest *TestUserREST) TestUpdateUserOKWithoutContextInfo() {
	// given
	user := rest.createRandomUser("TestUpdateUserOKWithoutContextInfo")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(rest.T(), user.FullName, *result.Data.Attributes.FullName)
	assert.Equal(rest.T(), user.ImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), identity.ProviderType, *result.Data.Attributes.ProviderType)
	assert.Equal(rest.T(), identity.Username, *result.Data.Attributes.Username)
	// when
	newEmail := "TestUpdateUserOKWithoutContextInfo-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserOKWithoutContextInfo"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	secureService, secureController := rest.SecuredController(identity)

	updateUserPayload := createUpdateUserPayloadWithoutContextInformation(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL)
	test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
}

//Pass " " as email in HTTP PATCH  /api/Users

func (rest *TestUserREST) TestUpdateUserWithInvalidEmail() {
	// given
	user := rest.createRandomUser("TestUpdateUserOKWithoutContextInfo")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)

	// when
	newEmail := " "
	newFullName := "TestUpdateUserOKWithoutContextInfo"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	secureService, secureController := rest.SecuredController(identity)

	//then
	updateUserPayload := createUpdateUserPayloadWithoutContextInformation(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL)
	test.UpdateUserBadRequest(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
}

//Pass " " as username in HTTP PATCH  /api/Users

func (rest *TestUserREST) TestUpdateUserWithInvalidUsername() {
	// given
	user := rest.createRandomUser("TestUpdateUserOKWithoutContextInfo")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"count":        3,
	}
	//when
	username := " "
	secureService, secureController := rest.SecuredController(identity)
	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, &username, nil, contextInformation)

	//then
	test.UpdateUserBadRequest(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
}

func (rest *TestUserREST) TestPatchUserContextInformation() {

	// given
	user := rest.createRandomUser("TestPatchUserContextInformation")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assertUser(rest.T(), result.Data, user, identity)
	// when
	secureService, secureController := rest.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"count":        3,
	}

	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	// then
	require.NotNil(rest.T(), result)

	// let's fetch it and validate the usual stuff.
	_, result = test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	require.NotNil(rest.T(), result)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)
	updatedContextInformation := result.Data.Attributes.ContextInformation

	// Before we PATCH, ensure that the 1st time update has worked well.
	assert.Equal(rest.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])
	countValue, ok := updatedContextInformation["count"].(float64)
	assert.True(rest.T(), ok)
	assert.Equal(rest.T(), contextInformation["count"], int(countValue))

	// Usual stuff done, now lets PATCH only 1 contextInformation attribute
	patchedContextInformation := map[string]interface{}{
		"count": 5,
	}

	updateUserPayload = createUpdateUserPayload(nil, nil, nil, nil, nil, nil, nil, nil, patchedContextInformation)
	_, result = test.UpdateUserOK(rest.T(), secureService.Context, secureService, secureController, updateUserPayload)
	require.NotNil(rest.T(), result)

	// let's fetch it and validate the usual stuff.
	_, result = test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	require.NotNil(rest.T(), result)
	updatedContextInformation = result.Data.Attributes.ContextInformation

	// what was NOT passed, should remain intact.
	assert.Equal(rest.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])

	// what WAS PASSED, should be updated.
	countValue, ok = updatedContextInformation["count"].(float64)
	assert.True(rest.T(), ok)
	assert.Equal(rest.T(), patchedContextInformation["count"], int(countValue))

}

func (rest *TestUserREST) TestUpdateUserUnauthorized() {
	// given
	user := rest.createRandomUser("TestUpdateUserUnauthorized")
	identity := rest.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(rest.T(), nil, nil, rest.usersController, identity.ID.String(), nil, nil)
	assert.Equal(rest.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(rest.T(), user.FullName, *result.Data.Attributes.FullName)
	assert.Equal(rest.T(), user.ImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(rest.T(), identity.ProviderType, *result.Data.Attributes.ProviderType)
	assert.Equal(rest.T(), identity.Username, *result.Data.Attributes.Username)
	newEmail := "TestUpdateUserUnauthorized-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserUnauthorized"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
	}

	updateUserPayload := createUpdateUserPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, nil, nil, nil, contextInformation)
	// when/then
	_, secureController := rest.SecuredController(identity)
	test.UpdateUserUnauthorized(rest.T(), context.Background(), nil, secureController, updateUserPayload)
}

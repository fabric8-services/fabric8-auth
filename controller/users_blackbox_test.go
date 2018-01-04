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
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormsupport"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/login/link"
	"github.com/fabric8-services/fabric8-auth/resource"
	testsupport "github.com/fabric8-services/fabric8-auth/test"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestUsers(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &TestUsersSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type TestUsersSuite struct {
	gormtestsupport.DBTestSuite
	svc            *goa.Service
	controller     *UsersController
	userRepo       account.UserRepository
	identityRepo   account.IdentityRepository
	profileService login.UserProfileService
	linkAPIService link.KeycloakIDPService
}

func (s *TestUsersSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.svc = goa.New("test")
	testAttributeValue := "a"
	dummyProfileResponse := createDummyUserProfileResponse(&testAttributeValue, &testAttributeValue, &testAttributeValue)
	keycloakUserProfileService := newDummyUserProfileService(dummyProfileResponse)
	s.profileService = keycloakUserProfileService
	s.linkAPIService = &dummyKeycloakLinkService{}
	s.controller = NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	s.userRepo = s.Application.Users()
	s.identityRepo = s.Application.Identities()
}

func (s *TestUsersSuite) SecuredController(identity account.Identity) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsUser("Users-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	return svc, controller
}

func (s *TestUsersSuite) SecuredUserController(identity account.Identity) (*goa.Service, *UserController) {
	svc := testsupport.ServiceAsUser("User-Service", identity)
	controller := NewUserController(s.svc, s.Application, nil, s.profileService, s.Configuration)
	return svc, controller
}

func (s *TestUsersSuite) SecuredServiceAccountController(identity account.Identity) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsServiceAccountUser("Users-ServiceAccount-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	return svc, controller
}

func (s *TestUsersSuite) TestShowUserOK() {
	// given user
	user := s.createRandomUser("TestShowUserOK")
	identity, err := testsupport.CreateTestUser(s.DB, &user)
	require.NoError(s.T(), err)

	// when
	res, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	// then
	assertUser(s.T(), result.Data, user, identity)
	assertSingleUserResponseHeaders(s.T(), res, result, user)
}

func (s *TestUsersSuite) TestShowUserOKUsingExpiredIfModifedSinceHeader() {
	// given user
	user := s.createRandomUser("TestShowUserOKUsingExpiredIfModifedSinceHeader")
	identity, err := testsupport.CreateTestUser(s.DB, &user)
	require.NoError(s.T(), err)

	// when
	ifModifiedSince := app.ToHTTPTime(user.UpdatedAt.Add(-1 * time.Hour))
	res, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), &ifModifiedSince, nil)
	// then
	assertUser(s.T(), result.Data, user, identity)
	assertSingleUserResponseHeaders(s.T(), res, result, user)
}

func (s *TestUsersSuite) TestShowUserOKUsingExpiredIfNoneMatchHeader() {
	// given user
	user := s.createRandomUser("TestShowUserOKUsingExpiredIfNoneMatchHeader")
	identity, err := testsupport.CreateTestUser(s.DB, &user)
	require.NoError(s.T(), err)

	// when
	ifNoneMatch := "foo"
	res, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, &ifNoneMatch)
	// then
	assertUser(s.T(), result.Data, user, identity)
	assertSingleUserResponseHeaders(s.T(), res, result, user)
}

func (s *TestUsersSuite) TestShowUserNotModifiedUsingIfModifedSinceHeader() {
	// given user
	user := s.createRandomUser("TestShowUserNotModifiedUsingIfModifedSinceHeader")
	identity, err := testsupport.CreateTestUser(s.DB, &user)
	require.NoError(s.T(), err)

	// when/then
	ifModifiedSince := app.ToHTTPTime(user.UpdatedAt.UTC())
	test.ShowUsersNotModified(s.T(), nil, nil, s.controller, identity.ID.String(), &ifModifiedSince, nil)
}

func (s *TestUsersSuite) TestShowUserNotModifiedUsingIfNoneMatchHeader() {
	// given user
	user := s.createRandomUser("TestShowUserNotModifiedUsingIfNoneMatchHeader")
	identity, err := testsupport.CreateTestUser(s.DB, &user)
	require.NoError(s.T(), err)

	// when/then
	ifNoneMatch := app.GenerateEntityTag(user)
	test.ShowUsersNotModified(s.T(), nil, nil, s.controller, identity.ID.String(), nil, &ifNoneMatch)
}

func (s *TestUsersSuite) TestShowUserNotFound() {
	// given user
	user := s.createRandomUser("TestShowUserNotFound")
	_, err := testsupport.CreateTestUser(s.DB, &user)
	require.NoError(s.T(), err)

	// when/then
	test.ShowUsersNotFound(s.T(), nil, nil, s.controller, uuid.NewV4().String(), nil, nil)
}

func (s *TestUsersSuite) TestShowUserBadRequest() {
	// given user
	user := s.createRandomUser("TestShowUserBadRequest")
	_, err := testsupport.CreateTestUser(s.DB, &user)
	require.NoError(s.T(), err)

	// when/then
	test.ShowUsersBadRequest(s.T(), nil, nil, s.controller, "invaliduuid", nil, nil)
}

func (s *TestUsersSuite) TestListUsersOK() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	identity1, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	identity2, err := testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	// when
	res, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity1.Username, nil, nil)
	// then
	assertUser(s.T(), findUser(identity1.ID, result.Data), user1, identity1)

	res, result = test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity2.Username, nil, nil)
	assertUser(s.T(), findUser(identity2.ID, result.Data), user2, identity2)
	assertMultiUsersResponseHeaders(s.T(), res, user2)
}

// a user should always have a KC identity, but just in case, the server should not fail
// to respond to the query if data some data is invalid.
func (s *TestUsersSuite) TestListUsersWithMissingKeycloakIdentityOK() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	identity1, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	identity1.ProviderType = ""
	err = s.Application.Identities().Save(context.Background(), &identity1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	identity2, err := testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)
	// when
	res, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity2.Username, nil, nil)
	// then
	assertUser(s.T(), findUser(identity2.ID, result.Data), user2, identity2)
	assertMultiUsersResponseHeaders(s.T(), res, user2)
}

func (s *TestUsersSuite) TestListUsersOKUsingExpiredIfModifiedSinceHeader() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOKUsingExpiredIfModifiedSinceHeader")
	identity1, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOKUsingExpiredIfModifiedSinceHeader2")
	identity2, err := testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	// when
	ifModifiedSinceHeader := app.ToHTTPTime(user2.UpdatedAt.Add(-1 * time.Hour))
	res, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity1.Username, &ifModifiedSinceHeader, nil)
	// then
	assertUser(s.T(), findUser(identity1.ID, result.Data), user1, identity1)

	res, result = test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity2.Username, &ifModifiedSinceHeader, nil)
	assertUser(s.T(), findUser(identity2.ID, result.Data), user2, identity2)
	assertMultiUsersResponseHeaders(s.T(), res, user2)
}

func (s *TestUsersSuite) TestListUsersOKUsingExpiredIfNoneMatchHeader() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOKUsingExpiredIfNoneMatchHeader")
	identity1, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOKUsingExpiredIfNoneMatchHeader2")
	identity2, err := testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	// when
	ifNoneMatch := "foo"
	res, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity1.Username, nil, &ifNoneMatch)
	// then
	assertUser(s.T(), findUser(identity1.ID, result.Data), user1, identity1)

	res, result = test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity2.Username, nil, &ifNoneMatch)
	assertUser(s.T(), findUser(identity2.ID, result.Data), user2, identity2)

	assertMultiUsersResponseHeaders(s.T(), res, user2)
}

func (s *TestUsersSuite) TestListUsersNotModifiedUsingIfModifiedSinceHeader() {
	// given user1
	user1 := s.createRandomUser("TestListUsersNotModifiedUsingIfModifiedSinceHeader")
	_, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersNotModifiedUsingIfModifiedSinceHeader2")
	_, err = testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	// when
	ifModifiedSinceHeader := app.ToHTTPTime(user2.UpdatedAt)
	res := test.ListUsersNotModified(s.T(), nil, nil, s.controller, nil, nil, &ifModifiedSinceHeader, nil)
	// then
	assertResponseHeaders(s.T(), res)
}

func (s *TestUsersSuite) TestListUsersByUsernameOK() {
	// given 3 users
	user1 := s.createRandomUser("TestListUsersOK1")
	identity11, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	user2 := s.createRandomUser("TestListUsersOK2")
	_, err = testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	user3 := s.createRandomUser("TestListUsersOK3")
	_, err = testsupport.CreateTestUser(s.DB, &user3)
	require.NoError(s.T(), err)

	// when
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity11.Username, nil, nil)
	// then
	for i, data := range result.Data {
		s.T().Log(fmt.Sprintf("Result #%d: %s %v", i, *data.ID, *data.Attributes.Username))
	}
	require.Len(s.T(), result.Data, 1)
	assertUser(s.T(), findUser(identity11.ID, result.Data), user1, identity11)
}

func (s *TestUsersSuite) TestListUsersByUsernameOKEmptyResult() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	_, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	_, err = testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	// when
	username := "foobar"
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &username, nil, nil)
	// then
	require.Len(s.T(), result.Data, 0)
}

func (s *TestUsersSuite) TestListUsersByUsernameNotModifiedUsingIfNoneMatchHeader() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	identity11, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	_, err = testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	_, filteredUsers := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity11.Username, nil, nil)
	// when/then
	ifNoneMatch := s.generateUsersTag(*filteredUsers)
	// when
	res := test.ListUsersNotModified(s.T(), nil, nil, s.controller, nil, &identity11.Username, nil, &ifNoneMatch)
	// then
	assertResponseHeaders(s.T(), res)
}

func (s *TestUsersSuite) TestListUsersByEmailOK() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	identity11, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	_, err = testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	// when
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, &user1.Email, nil, nil, nil)
	// then
	for i, data := range result.Data {
		s.T().Log(fmt.Sprintf("Result #%d: %s %v", i, *data.ID, *data.Attributes.Username))
	}
	// even though 2 identites were created, only 1 app user was returned.
	// this is because only we currently consider only kc identites.
	require.Len(s.T(), result.Data, 1)
	assertUser(s.T(), findUser(identity11.ID, result.Data), user1, identity11)
}

func (s *TestUsersSuite) TestListUsersByEmailOKEmptyResult() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	_, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	_, err = testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	// when
	email := "foo@bar.com"
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, &email, nil, nil, nil)
	// then
	require.Len(s.T(), result.Data, 0)
}

func (s *TestUsersSuite) TestHideEmailOK() {
	boolTrue := true

	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	identity, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	secureService, _ := s.SecuredController(identity)

	// when
	email := user1.Email

	// by default, email is public.
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, &email, nil, nil, nil)
	returnedUser := result.Data[0].Attributes
	require.Equal(s.T(), email, *returnedUser.Email)
	require.False(s.T(), *returnedUser.EmailPrivate)

	// check for /api/users/<ID>
	// should show public email when not made private.
	_, singleResult := test.ShowUsersOK(s.T(), secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
	returnedUser = singleResult.Data.Attributes
	require.Equal(s.T(), email, *returnedUser.Email)
	require.False(s.T(), *returnedUser.EmailPrivate)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}
	updateUserPayload := createUpdateUserPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	updateUserPayload.Data.Attributes.EmailPrivate = &boolTrue
	secureUserService, secureUserController := s.SecuredUserController(identity)
	_, updateResult := test.UpdateUserOK(s.T(), secureUserService.Context, secureUserService, secureUserController, updateUserPayload)

	// Email will be visible to the one who it belongs to
	require.True(s.T(), *updateResult.Data.Attributes.EmailPrivate)
	require.Equal(s.T(), user1.Email, *updateResult.Data.Attributes.Email)

	// But when you try to access the same with an API which doesn't respect auth,
	// it wouldn't be visible.
	_, result = test.ListUsersOK(s.T(), nil, nil, s.controller, &email, nil, nil, nil)
	returnedUserResult := result.Data[0]
	require.Equal(s.T(), "", *returnedUserResult.Attributes.Email)

	// the /api/users/<ID> endpoint should hide out the email.
	_, showUserResponse := test.ShowUsersOK(s.T(), secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
	require.NotEqual(s.T(), user1.Email, *showUserResponse.Data.Attributes.Email)
	require.Equal(s.T(), "", *showUserResponse.Data.Attributes.Email)
	require.True(s.T(), *showUserResponse.Data.Attributes.EmailPrivate)

}

func (s *TestUsersSuite) TestListUsersByEmailNotModifiedUsingIfNoneMatchHeader() {

	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	_, err := testsupport.CreateTestUser(s.DB, &user1)
	require.NoError(s.T(), err)

	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	_, err = testsupport.CreateTestUser(s.DB, &user2)
	require.NoError(s.T(), err)

	_, filteredUsers := test.ListUsersOK(s.T(), nil, nil, s.controller, &user1.Email, nil, nil, nil)
	// when
	ifNoneMatch := s.generateUsersTag(*filteredUsers)
	res := test.ListUsersNotModified(s.T(), nil, nil, s.controller, &user1.Email, nil, nil, &ifNoneMatch)
	// then
	assertResponseHeaders(s.T(), res)
}

func (s *TestUsersSuite) createRandomUser(fullname string) account.User {
	user := account.User{
		Email:        uuid.NewV4().String() + "primaryForUpdat7e@example.com",
		FullName:     fullname,
		ImageURL:     "someURLForUpdate",
		ID:           uuid.NewV4(),
		Company:      uuid.NewV4().String() + "company",
		Cluster:      "My OSO cluster url",
		EmailPrivate: false, // being explicit
	}
	return user
}

func findUser(id uuid.UUID, userData []*app.UserData) *app.UserData {
	for _, user := range userData {
		if *user.ID == id.String() {
			return user
		}
	}
	return nil
}

func assertCreatedUser(t *testing.T, actual *app.UserData, expectedUser account.User, expectedIdentity account.Identity) {
	require.NotNil(t, actual)
	assert.Equal(t, expectedIdentity.Username, *actual.Attributes.Username)
	if expectedIdentity.ProviderType == "" {
		assert.Equal(t, account.KeycloakIDP, *actual.Attributes.ProviderType)
	} else {
		assert.Equal(t, expectedIdentity.ProviderType, *actual.Attributes.ProviderType)
	}
	assert.Equal(t, expectedIdentity.RegistrationCompleted, *actual.Attributes.RegistrationCompleted)
	assert.Equal(t, expectedUser.FullName, *actual.Attributes.FullName)
	assert.Equal(t, expectedUser.ImageURL, *actual.Attributes.ImageURL)
	assert.Equal(t, expectedUser.Email, *actual.Attributes.Email)
	assert.Equal(t, expectedUser.Company, *actual.Attributes.Company)
	assert.Equal(t, expectedUser.Cluster, *actual.Attributes.Cluster)
	assert.Equal(t, expectedUser.URL, *actual.Attributes.URL)
	assert.Equal(t, expectedUser.Bio, *actual.Attributes.Bio)
	assertContextInformation(t, expectedUser.ContextInformation, actual.Attributes.ContextInformation)
}

func assertContextInformation(t *testing.T, expected account.ContextInformation, actual map[string]interface{}) {
	if expected == nil {
		require.Equal(t, 0, len(actual))
		return
	}
	require.Equal(t, len(expected), len(actual))
	for key, value := range expected {
		actualValue, found := actual[key]
		assert.True(t, found, fmt.Sprintf("key [%s] not found", key))
		assert.Equal(t, value, actualValue)
	}
}

func assertUser(t *testing.T, actual *app.UserData, expectedUser account.User, expectedIdentity account.Identity) {
	require.NotNil(t, actual)
	assert.Equal(t, expectedIdentity.ID.String(), *actual.ID)
	assert.Equal(t, expectedIdentity.Username, *actual.Attributes.Username)
	assert.Equal(t, expectedIdentity.ProviderType, *actual.Attributes.ProviderType)
	assert.Equal(t, expectedUser.FullName, *actual.Attributes.FullName)
	assert.Equal(t, expectedUser.ImageURL, *actual.Attributes.ImageURL)
	if !*actual.Attributes.EmailPrivate {
		assert.Equal(t, expectedUser.Email, *actual.Attributes.Email)
	} else {
		assert.Equal(t, "", *actual.Attributes.Email)
	}
	assert.Equal(t, expectedUser.ID.String(), *actual.Attributes.UserID)
	assert.Equal(t, expectedIdentity.ID.String(), *actual.Attributes.IdentityID)
	assert.Equal(t, expectedIdentity.ProviderType, *actual.Attributes.ProviderType)
	assert.Equal(t, expectedUser.Company, *actual.Attributes.Company)
	assert.Equal(t, expectedUser.Cluster, *actual.Attributes.Cluster)
}

func assertSingleUserResponseHeaders(t *testing.T, res http.ResponseWriter, appUser *app.User, modelUser account.User) {
	require.NotNil(t, res.Header()[app.LastModified])
	assert.Equal(t, getUserUpdatedAt(*appUser).UTC().Format(http.TimeFormat), res.Header()[app.LastModified][0])
	require.NotNil(t, res.Header()[app.CacheControl])
	require.NotNil(t, res.Header()[app.ETag])
	assert.Equal(t, app.GenerateEntityTag(modelUser), res.Header()[app.ETag][0])
}

func assertMultiUsersResponseHeaders(t *testing.T, res http.ResponseWriter, lastCreatedUser account.User) {
	require.NotNil(t, res.Header()[app.LastModified])
	assert.Equal(t, lastCreatedUser.UpdatedAt.Truncate(time.Second).UTC().Format(http.TimeFormat), res.Header()[app.LastModified][0])
	require.NotNil(t, res.Header()[app.CacheControl])
	require.NotNil(t, res.Header()[app.ETag])
}

func getUserUpdatedAt(appUser app.User) time.Time {
	return appUser.Data.Attributes.UpdatedAt.Truncate(time.Second).UTC()
}

func (s *TestUsersSuite) generateUsersTag(allUsers app.UserArray) string {
	entities := make([]app.ConditionalRequestEntity, len(allUsers.Data))
	for i, user := range allUsers.Data {
		userID, err := uuid.FromString(*user.Attributes.UserID)
		require.Nil(s.T(), err)
		entities[i] = account.User{
			ID: userID,
			Lifecycle: gormsupport.Lifecycle{
				UpdatedAt: *user.Attributes.UpdatedAt,
			},
		}
	}
	log.Info(nil, map[string]interface{}{"users": len(allUsers.Data), "etag": app.GenerateEntitiesTag(entities)}, "generate users tag")
	return app.GenerateEntitiesTag(entities)
}

type dummyKeycloakLinkService struct{}

func (d *dummyKeycloakLinkService) Create(ctx context.Context, keycloakLinkIDPRequest *link.KeycloakLinkIDPRequest, protectedAccessToken string, keycloakIDPLinkURL string) error {
	return nil
}

type dummyUserProfileService struct {
	dummyGetResponse *login.KeycloakUserProfileResponse
}

func newDummyUserProfileService(dummyGetResponse *login.KeycloakUserProfileResponse) *dummyUserProfileService {
	return &dummyUserProfileService{
		dummyGetResponse: dummyGetResponse,
	}
}

func (d *dummyUserProfileService) Update(ctx context.Context, keycloakUserProfile *login.KeycloakUserProfile, accessToken string, keycloakProfileURL string) error {
	return nil
}

func (d *dummyUserProfileService) Get(ctx context.Context, accessToken string, keycloakProfileURL string) (*login.KeycloakUserProfileResponse, error) {
	return d.dummyGetResponse, nil
}

func (d *dummyUserProfileService) CreateOrUpdate(ctx context.Context, keycloakUserProfile *login.KeytcloakUserRequest, accessToken string, keycloakProfileURL string) (*string, bool, error) {
	url := "https://someurl/pathinkeycloakurl/" + uuid.NewV4().String()
	return &url, true, nil
}

func (d *dummyUserProfileService) SetDummyGetResponse(dummyGetResponse *login.KeycloakUserProfileResponse) {
	d.dummyGetResponse = dummyGetResponse
}

func createDummyUserProfileResponse(updatedBio, updatedImageURL, updatedURL *string) *login.KeycloakUserProfileResponse {
	profile := &login.KeycloakUserProfileResponse{}
	profile.Attributes = &login.KeycloakUserProfileAttributes{}

	(*profile.Attributes)[login.BioAttributeName] = []string{*updatedBio}
	(*profile.Attributes)[login.ImageURLAttributeName] = []string{*updatedImageURL}
	(*profile.Attributes)[login.URLAttributeName] = []string{*updatedURL}

	return profile

}

func (s *TestUsersSuite) TestCreateUserAsServiceAccountWithAllFieldsOK() {

	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity
	identity.User = user
	identity.ProviderType = account.KeycloakIDP
	identity.RegistrationCompleted = true

	user.ContextInformation = map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}
	user.Company = "randomCompany"
	user.Bio = "some bio"
	user.ImageURL = "some image"
	user.URL = "some url"
	user.Cluster = "some cluster"
	rhdUserName := "somerhdusername"
	approved := false

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)

	// when
	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, &rhdUserName, &user.Cluster, &identity.RegistrationCompleted, &approved, user.ContextInformation)

	// then
	_, appUser := test.CreateUsersOK(s.T(), secureService.Context, secureService, secureController, createUserPayload)
	assertCreatedUser(s.T(), appUser.Data, user, identity)
}

func (s *TestUsersSuite) TestCreateUserAsServiceAccountForExistingUserInDbFails() {
	user := testsupport.TestUser
	identity := testsupport.TestIdentity
	identity.User = user
	identity.ProviderType = ""
	user.Cluster = "some cluster"

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)

	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, nil, nil, nil, nil, nil, &identity.Username, nil, &user.Cluster, nil, nil, nil)

	// First attempt should be OK
	test.CreateUsersOK(s.T(), secureService.Context, secureService, secureController, createUserPayload)

	// Another call with the same email and username should fail
	test.CreateUsersConflict(s.T(), secureService.Context, secureService, secureController, createUserPayload)

	newEmail := uuid.NewV4().String() + user.Email
	payloadWithSameUsername := createCreateUsersAsServiceAccountPayload(&newEmail, nil, nil, nil, nil, nil, &identity.Username, nil, &user.Cluster, nil, nil, nil)
	// Another call with the same username should fail
	test.CreateUsersConflict(s.T(), secureService.Context, secureService, secureController, payloadWithSameUsername)

	newUsername := uuid.NewV4().String() + identity.Username
	payloadWithSameEmail := createCreateUsersAsServiceAccountPayload(&user.Email, nil, nil, nil, nil, nil, &newUsername, nil, &user.Cluster, nil, nil, nil)
	// Another call with the same email should fail
	test.CreateUsersConflict(s.T(), secureService.Context, secureService, secureController, payloadWithSameEmail)
}

func (s *TestUsersSuite) TestCreateUserAsServiceAccountWithRequiredFieldsOnlyOK() {
	user := testsupport.TestUser
	identity := testsupport.TestIdentity
	identity.User = user
	identity.ProviderType = ""
	user.FullName = ""
	user.Cluster = "some cluster"

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)

	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, nil, nil, nil, nil, nil, &identity.Username, nil, &user.Cluster, nil, nil, nil)

	// With only required fields should be OK
	_, appUser := test.CreateUsersOK(s.T(), secureService.Context, secureService, secureController, createUserPayload)
	assertCreatedUser(s.T(), appUser.Data, user, identity)
}

func (s *TestUsersSuite) TestCreateUserAsServiceAccountWithMissingRequiredFieldsFails() {
	user := testsupport.TestUser
	identity := testsupport.TestIdentity
	cluster := "some cluster"

	// Missing username
	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, nil, nil, nil, nil, nil, nil, nil, &cluster, nil, nil, nil)
	require.NotNil(s.T(), createUserPayload.Validate())

	// Missing email
	createUserPayload = createCreateUsersAsServiceAccountPayload(nil, nil, nil, nil, nil, nil, &identity.Username, nil, &cluster, nil, nil, nil)
	require.NotNil(s.T(), createUserPayload.Validate())

	// Missing cluster
	createUserPayload = createCreateUsersAsServiceAccountPayload(&user.Email, nil, nil, nil, nil, nil, &identity.Username, nil, nil, nil, nil, nil)
	require.NotNil(s.T(), createUserPayload.Validate())
}

func (s *TestUsersSuite) TestCreateUserAsServiceAccountUnauthorized() {
	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestIdentity)

	// then
	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, nil, &user.Cluster, &identity.RegistrationCompleted, nil, user.ContextInformation)
	test.CreateUsersUnauthorized(s.T(), secureService.Context, secureService, secureController, createUserPayload)
}

func (s *TestUsersSuite) TestCreateUserAsNonServiceAccountUnauthorized() {
	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity

	secureService, secureController := s.SecuredController(testsupport.TestIdentity)

	// then
	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, nil, &user.Cluster, &identity.RegistrationCompleted, nil, user.ContextInformation)
	test.CreateUsersUnauthorized(s.T(), secureService.Context, secureService, secureController, createUserPayload)
}

func (s *TestUsersSuite) TestCreateUserUnauthorized() {
	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity

	// then
	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, nil, &user.Cluster, &identity.RegistrationCompleted, nil, user.ContextInformation)
	test.CreateUsersUnauthorized(s.T(), context.Background(), nil, s.controller, createUserPayload)
}

func createCreateUsersAsServiceAccountPayload(email, fullName, bio, imageURL, profileURL, company, username, rhdUsername, cluster *string, registrationCompleted, approved *bool, contextInformation map[string]interface{}) *app.CreateUsersPayload {
	providerType := "SomeRandomType" // Should be ignored

	attributes := app.CreateIdentityDataAttributes{
		//UserID:                userID,
		Approved:              approved,
		RhdUsername:           rhdUsername,
		FullName:              fullName,
		Bio:                   bio,
		ImageURL:              imageURL,
		URL:                   profileURL,
		Company:               company,
		ContextInformation:    contextInformation,
		RegistrationCompleted: registrationCompleted,
		ProviderType:          &providerType,
	}

	if email != nil {
		attributes.Email = *email
	}
	if username != nil {
		attributes.Username = *username
	}
	if cluster != nil {
		attributes.Cluster = *cluster
	}

	return &app.CreateUsersPayload{
		Data: &app.CreateUserData{
			Type:       "identities",
			Attributes: &attributes,
		},
	}
}

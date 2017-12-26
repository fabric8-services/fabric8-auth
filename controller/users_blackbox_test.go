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
	s.controller.RemoteWITService = &dummyRemoteWITService{}
}

func (s *TestUsersSuite) SecuredController(identity account.Identity) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsUser("Users-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	controller.RemoteWITService = &dummyRemoteWITService{}
	return svc, controller
}

func (s *TestUsersSuite) SecuredServiceAccountController(identity account.Identity) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsServiceAccountUser("Users-ServiceAccount-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	controller.RemoteWITService = &dummyRemoteWITService{}
	return svc, controller
}

func (s *TestUsersSuite) TestUpdateUserOK() {
	// given
	user := s.createRandomUser("TestUpdateUserOK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(s.T(), user.FullName, *result.Data.Attributes.FullName)
	assert.Equal(s.T(), user.ImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(s.T(), identity.ProviderType, *result.Data.Attributes.ProviderType)
	assert.Equal(s.T(), identity.Username, *result.Data.Attributes.Username)
	assert.Equal(s.T(), user.Company, *result.Data.Attributes.Company)

	// when
	newEmail := "TestUpdateUserOK-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserOK"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	newCompany := "updateCompany " + uuid.NewV4().String()
	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}
	//secureController, secureService := createSecureController(t, identity)
	updateUsersPayload := createUpdateUsersPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, &newCompany, nil, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)

	// then
	require.NotNil(s.T(), result)
	// let's fetch it and validate
	_, result = test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	require.NotNil(s.T(), result)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(s.T(), newFullName, *result.Data.Attributes.FullName)
	assert.Equal(s.T(), newImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(s.T(), newBio, *result.Data.Attributes.Bio)
	assert.Equal(s.T(), newProfileURL, *result.Data.Attributes.URL)
	assert.Equal(s.T(), newCompany, *result.Data.Attributes.Company)

	updatedContextInformation := result.Data.Attributes.ContextInformation
	assert.Equal(s.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])

	countValue, ok := updatedContextInformation["count"].(float64)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), contextInformation["count"], int(countValue))
	assert.Equal(s.T(), contextInformation["rate"], updatedContextInformation["rate"])
}

func (s *TestUsersSuite) TestUpdateUserNameMulitpleTimesForbidden() {

	user := s.createRandomUser("OK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)

	newUserName := identity.Username + uuid.NewV4().String()
	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	// you can update username multiple times.
	// also omit registrationCompleted
	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, &newUserName, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)

	boolTrue := true
	updateUsersPayload = createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, &newUserName, &boolTrue, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)

	// next attempt should fail.
	newUserName = identity.Username + uuid.NewV4().String()
	updateUsersPayload = createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, &newUserName, nil, contextInformation)
	test.UpdateUsersForbidden(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
}

func (s *TestUsersSuite) TestUpdateUserNameMulitpleTimesOK() {

	user := s.createRandomUser("OK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)

	newUserName := identity.Username // new username = old userame
	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, &newUserName, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	require.False(s.T(), *result.Data.Attributes.RegistrationCompleted)

	// next attempt should PASS.
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	require.False(s.T(), *result.Data.Attributes.RegistrationCompleted)

}

func (s *TestUsersSuite) TestUpdateRegistrationCompletedOK() {
	user := s.createRandomUser("OK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)

	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	require.False(s.T(), *result.Data.Attributes.RegistrationCompleted)

	// next attempt should PASS.
	boolTrue := true
	updateUsersPayload = createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, nil, &boolTrue, contextInformation)
	test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
}

func (s *TestUsersSuite) TestUpdateRegistrationCompletedBadRequest() {
	user := s.createRandomUser("OKRegCompleted")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)

	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	require.False(s.T(), *result.Data.Attributes.RegistrationCompleted)

	// next attempt should fail.
	boolFalse := false
	updateUsersPayload = createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, nil, &boolFalse, contextInformation)
	test.UpdateUsersBadRequest(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)

}

func (s *TestUsersSuite) TestUpdateRegistrationCompletedAndUsernameOK() {

	// In this test case, we send both registrationCompleted=True and an updated username
	// as part of HTTP PATCH.

	user := s.createRandomUser("OKRegCompleted")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)

	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	require.False(s.T(), *result.Data.Attributes.RegistrationCompleted)

	boolTrue := true
	newUserName := identity.Username + uuid.NewV4().String()
	updateUsersPayload = createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, &newUserName, &boolTrue, contextInformation)
	test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)

}

func (s *TestUsersSuite) TestUpdateExistingUsernameForbidden() {
	// create 2 users.
	user := s.createRandomUser("OK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)

	user2 := s.createRandomUser("OK2")
	identity2 := s.createRandomIdentity(user2, account.KeycloakIDP)
	_, result2 := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity2.ID.String(), nil, nil)
	assert.Equal(s.T(), identity2.ID.String(), *result2.Data.ID)

	// try updating using the username of an existing ( just created ) user.
	secureService, secureController := s.SecuredController(identity2)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	newUserName := identity.Username
	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, &newUserName, nil, contextInformation)
	test.UpdateUsersBadRequest(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
}

func (s *TestUsersSuite) TestUpdateExistingEmailForbidden() {
	// create 2 users.
	user := s.createRandomUser("OK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)

	user2 := s.createRandomUser("OK2")
	identity2 := s.createRandomIdentity(user2, account.KeycloakIDP)
	_, result2 := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity2.ID.String(), nil, nil)
	assert.Equal(s.T(), identity2.ID.String(), *result2.Data.ID)

	// try updating using the email of an existing ( just created ) user.
	secureService, secureController := s.SecuredController(identity2)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
	}

	newEmail := user.Email
	updateUsersPayload := createUpdateUsersPayload(&newEmail, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	test.UpdateUsersBadRequest(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
}

func (s *TestUsersSuite) TestUpdateUserVariableSpacesInNameOK() {

	// given
	user := s.createRandomUser("OK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assertUser(s.T(), result.Data, user, identity)
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

	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}
	//secureController, secureService := createSecureController(t, identity)
	updateUsersPayload := createUpdateUsersPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, &newCompany, nil, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	// then
	require.NotNil(s.T(), result)
	// let's fetch it and validate
	_, result = test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	require.NotNil(s.T(), result)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(s.T(), newFullName, *result.Data.Attributes.FullName)
	assert.Equal(s.T(), newImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(s.T(), newBio, *result.Data.Attributes.Bio)
	assert.Equal(s.T(), newProfileURL, *result.Data.Attributes.URL)
	assert.Equal(s.T(), newCompany, *result.Data.Attributes.Company)

	updatedContextInformation := result.Data.Attributes.ContextInformation
	assert.Equal(s.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])
	countValue, ok := updatedContextInformation["count"].(float64)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), contextInformation["count"], int(countValue))
	assert.Equal(s.T(), contextInformation["rate"], updatedContextInformation["rate"])
}

//Test to unset variable in contextInformation

func (s *TestUsersSuite) TestUpdateUserUnsetVariableInContextInfo() {
	// given
	user := s.createRandomUser("TestUpdateUserUnsetVariableInContextInfo")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(s.T(), user.FullName, *result.Data.Attributes.FullName)
	assert.Equal(s.T(), user.ImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(s.T(), identity.ProviderType, *result.Data.Attributes.ProviderType)
	assert.Equal(s.T(), identity.Username, *result.Data.Attributes.Username)

	// when
	newEmail := "TestUpdateUserUnsetVariableInContextInfo-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserUnsetVariableInContextInfo"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	secureService, secureController := s.SecuredController(identity)
	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}
	//secureController, secureService := createSecureController(t, identity)
	updateUsersPayload := createUpdateUsersPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, nil, nil, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	// then
	require.NotNil(s.T(), result)
	// let's fetch it and validate the usual stuff.
	_, result = test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	require.NotNil(s.T(), result)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(s.T(), newFullName, *result.Data.Attributes.FullName)
	assert.Equal(s.T(), newImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(s.T(), newBio, *result.Data.Attributes.Bio)
	assert.Equal(s.T(), newProfileURL, *result.Data.Attributes.URL)
	updatedContextInformation := result.Data.Attributes.ContextInformation
	assert.Equal(s.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])

	// Usual stuff done, now lets unset
	contextInformation = map[string]interface{}{
		"last_visited": nil,
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}

	updateUsersPayload = createUpdateUsersPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, nil, nil, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	// then
	require.NotNil(s.T(), result)
	// let's fetch it and validate the usual stuff.
	_, result = test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	require.NotNil(s.T(), result)
	updatedContextInformation = result.Data.Attributes.ContextInformation

	// what was passed as non-nill should be intact.
	assert.Equal(s.T(), contextInformation["space"], updatedContextInformation["space"])

	// what was pass as nil should not be found!
	_, ok := updatedContextInformation["last_visited"]
	assert.Equal(s.T(), false, ok)
}

//Pass no contextInformation and no one complains.
//This is as per general service behaviour.

func (s *TestUsersSuite) TestUpdateUserOKWithoutContextInfo() {
	// given
	user := s.createRandomUser("TestUpdateUserOKWithoutContextInfo")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(s.T(), user.FullName, *result.Data.Attributes.FullName)
	assert.Equal(s.T(), user.ImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(s.T(), identity.ProviderType, *result.Data.Attributes.ProviderType)
	assert.Equal(s.T(), identity.Username, *result.Data.Attributes.Username)
	// when
	newEmail := "TestUpdateUserOKWithoutContextInfo-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserOKWithoutContextInfo"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	secureService, secureController := s.SecuredController(identity)

	updateUsersPayload := createUpdateUsersPayloadWithoutContextInformation(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL)
	test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
}

//Pass " " as email in HTTP PATCH  /api/Users

func (s *TestUsersSuite) TestUpdateUserWithInvalidEmail() {
	// given
	user := s.createRandomUser("TestUpdateUserOKWithoutContextInfo")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)

	// when
	newEmail := " "
	newFullName := "TestUpdateUserOKWithoutContextInfo"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	secureService, secureController := s.SecuredController(identity)

	//then
	updateUsersPayload := createUpdateUsersPayloadWithoutContextInformation(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL)
	test.UpdateUsersBadRequest(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
}

//Pass " " as username in HTTP PATCH  /api/Users

func (s *TestUsersSuite) TestUpdateUserWithInvalidUsername() {
	// given
	user := s.createRandomUser("TestUpdateUserOKWithoutContextInfo")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"count":        3,
	}
	//when
	username := " "
	secureService, secureController := s.SecuredController(identity)
	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, &username, nil, contextInformation)

	//then
	test.UpdateUsersBadRequest(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
}

func (s *TestUsersSuite) TestPatchUserContextInformation() {

	// given
	user := s.createRandomUser("TestPatchUserContextInformation")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assertUser(s.T(), result.Data, user, identity)
	// when
	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"count":        3,
	}
	//secureController, secureService := createSecureController(t, identity)
	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	// then
	require.NotNil(s.T(), result)

	// let's fetch it and validate the usual stuff.
	_, result = test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	require.NotNil(s.T(), result)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)
	updatedContextInformation := result.Data.Attributes.ContextInformation

	// Before we PATCH, ensure that the 1st time update has worked well.
	assert.Equal(s.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])
	countValue, ok := updatedContextInformation["count"].(float64)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), contextInformation["count"], int(countValue))

	// Usual stuff done, now lets PATCH only 1 contextInformation attribute
	patchedContextInformation := map[string]interface{}{
		"count": 5,
	}

	updateUsersPayload = createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, nil, nil, patchedContextInformation)
	_, result = test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
	require.NotNil(s.T(), result)

	// let's fetch it and validate the usual stuff.
	_, result = test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	require.NotNil(s.T(), result)
	updatedContextInformation = result.Data.Attributes.ContextInformation

	// what was NOT passed, should remain intact.
	assert.Equal(s.T(), contextInformation["last_visited"], updatedContextInformation["last_visited"])

	// what WAS PASSED, should be updated.
	countValue, ok = updatedContextInformation["count"].(float64)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), patchedContextInformation["count"], int(countValue))

}

func (s *TestUsersSuite) TestUpdateUserUnauthorized() {
	// given
	user := s.createRandomUser("TestUpdateUserUnauthorized")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assert.Equal(s.T(), identity.ID.String(), *result.Data.ID)
	assert.Equal(s.T(), user.FullName, *result.Data.Attributes.FullName)
	assert.Equal(s.T(), user.ImageURL, *result.Data.Attributes.ImageURL)
	assert.Equal(s.T(), identity.ProviderType, *result.Data.Attributes.ProviderType)
	assert.Equal(s.T(), identity.Username, *result.Data.Attributes.Username)
	newEmail := "TestUpdateUserUnauthorized-" + uuid.NewV4().String() + "@email.com"
	newFullName := "TestUpdateUserUnauthorized"
	newImageURL := "http://new.image.io/imageurl"
	newBio := "new bio"
	newProfileURL := "http://new.profile.url/url"
	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
	}
	//secureController, secureService := createSecureController(t, identity)
	updateUsersPayload := createUpdateUsersPayload(&newEmail, &newFullName, &newBio, &newImageURL, &newProfileURL, nil, nil, nil, contextInformation)
	// when/then
	test.UpdateUsersUnauthorized(s.T(), context.Background(), nil, s.controller, updateUsersPayload)
}

func (s *TestUsersSuite) TestShowUserOK() {
	// given user
	user := s.createRandomUser("TestShowUserOK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	// when
	res, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	// then
	assertUser(s.T(), result.Data, user, identity)
	assertSingleUserResponseHeaders(s.T(), res, result, user)
}

func (s *TestUsersSuite) TestShowUserOKUsingExpiredIfModifedSinceHeader() {
	// given user
	user := s.createRandomUser("TestShowUserOKUsingExpiredIfModifedSinceHeader")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
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
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
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
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	// when/then
	ifModifiedSince := app.ToHTTPTime(user.UpdatedAt.UTC())
	test.ShowUsersNotModified(s.T(), nil, nil, s.controller, identity.ID.String(), &ifModifiedSince, nil)
}

func (s *TestUsersSuite) TestShowUserNotModifiedUsingIfNoneMatchHeader() {
	// given user
	user := s.createRandomUser("TestShowUserNotModifiedUsingIfNoneMatchHeader")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	// when/then
	ifNoneMatch := app.GenerateEntityTag(user)
	test.ShowUsersNotModified(s.T(), nil, nil, s.controller, identity.ID.String(), nil, &ifNoneMatch)
}

func (s *TestUsersSuite) TestShowUserNotFound() {
	// given user
	user := s.createRandomUser("TestShowUserNotFound")
	s.createRandomIdentity(user, account.KeycloakIDP)
	// when/then
	test.ShowUsersNotFound(s.T(), nil, nil, s.controller, uuid.NewV4().String(), nil, nil)
}

func (s *TestUsersSuite) TestShowUserBadRequest() {
	// given user
	user := s.createRandomUser("TestShowUserBadRequest")
	s.createRandomIdentity(user, account.KeycloakIDP)
	// when/then
	test.ShowUsersBadRequest(s.T(), nil, nil, s.controller, "invaliduuid", nil, nil)
}

func (s *TestUsersSuite) TestListUsersOK() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	identity1 := s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, account.KeycloakIDP)
	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	identity2 := s.createRandomIdentity(user2, account.KeycloakIDP)
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
	s.createRandomUser("TestListUsersOK1")
	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	identity2 := s.createRandomIdentity(user2, account.KeycloakIDP)
	// when
	res, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity2.Username, nil, nil)
	// then
	assertUser(s.T(), findUser(identity2.ID, result.Data), user2, identity2)
	assertMultiUsersResponseHeaders(s.T(), res, user2)
}

func (s *TestUsersSuite) TestListUsersOKUsingExpiredIfModifiedSinceHeader() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOKUsingExpiredIfModifiedSinceHeader")
	identity1 := s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, account.KeycloakIDP)
	// given user2
	user2 := s.createRandomUser("TestListUsersOKUsingExpiredIfModifiedSinceHeader2")
	identity2 := s.createRandomIdentity(user2, account.KeycloakIDP)
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
	identity1 := s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, "github-test")
	// given user2
	user2 := s.createRandomUser("TestListUsersOKUsingExpiredIfNoneMatchHeader2")
	identity2 := s.createRandomIdentity(user2, account.KeycloakIDP)
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
	s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, "github-test")
	// given user2
	user2 := s.createRandomUser("TestListUsersNotModifiedUsingIfModifiedSinceHeader2")
	s.createRandomIdentity(user2, account.KeycloakIDP)
	// when
	ifModifiedSinceHeader := app.ToHTTPTime(user2.UpdatedAt)
	res := test.ListUsersNotModified(s.T(), nil, nil, s.controller, nil, nil, &ifModifiedSinceHeader, nil)
	// then
	assertResponseHeaders(s.T(), res)
}

func (s *TestUsersSuite) TestListUsersByUsernameOK() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	identity11 := s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, "github-test")
	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	s.createRandomIdentity(user2, account.KeycloakIDP)
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
	s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, "github-test")
	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	s.createRandomIdentity(user2, account.KeycloakIDP)
	// when
	username := "foobar"
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &username, nil, nil)
	// then
	require.Len(s.T(), result.Data, 0)
}

func (s *TestUsersSuite) TestListUsersByUsernameNotModifiedUsingIfNoneMatchHeader() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	identity11 := s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, "github-test")
	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	s.createRandomIdentity(user2, account.KeycloakIDP)
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
	identity11 := s.createRandomIdentity(user1, account.KeycloakIDP)
	_ = s.createRandomIdentity(user1, "xyz-idp")

	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	s.createRandomIdentity(user2, account.KeycloakIDP)
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
	s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, "xyz-idp")
	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	s.createRandomIdentity(user2, account.KeycloakIDP)
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
	identity := s.createRandomIdentity(user1, account.KeycloakIDP)

	// when
	email := user1.Email

	// by default, email is public.
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, &email, nil, nil, nil)
	returnedUser := result.Data[0].Attributes
	require.Equal(s.T(), email, *returnedUser.Email)
	require.False(s.T(), *returnedUser.EmailPrivate)

	secureService, secureController := s.SecuredController(identity)

	contextInformation := map[string]interface{}{
		"last_visited": "yesterday",
		"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
		"rate":         100.00,
		"count":        3,
	}
	updateUsersPayload := createUpdateUsersPayload(nil, nil, nil, nil, nil, nil, nil, nil, contextInformation)
	updateUsersPayload.Data.Attributes.EmailPrivate = &boolTrue
	_, updateResult := test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)

	// Email will be visible to the one who it belongs to
	require.True(s.T(), *updateResult.Data.Attributes.EmailPrivate)
	require.Equal(s.T(), user1.Email, *updateResult.Data.Attributes.Email)

	// But when you try to access the same with an API which doesn't respect auth,
	// it wouldn't be visible.
	_, result = test.ListUsersOK(s.T(), nil, nil, s.controller, &email, nil, nil, nil)
	returnedUserResult := result.Data[0]
	require.Equal(s.T(), "", *returnedUserResult.Attributes.Email)

	// even though the email_hidden=true,
	// the email address is visible to the user if her user token is passed.
	_, showUserResponse := test.ShowUsersOK(s.T(), secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
	require.Equal(s.T(), user1.Email, *showUserResponse.Data.Attributes.Email)
	require.True(s.T(), *showUserResponse.Data.Attributes.EmailPrivate)
}

func (s *TestUsersSuite) TestListUsersByEmailNotModifiedUsingIfNoneMatchHeader() {
	// given user1
	user1 := s.createRandomUser("TestListUsersOK1")
	s.createRandomIdentity(user1, account.KeycloakIDP)
	s.createRandomIdentity(user1, "xyz-idp")
	// given user2
	user2 := s.createRandomUser("TestListUsersOK2")
	s.createRandomIdentity(user2, account.KeycloakIDP)
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
	err := s.userRepo.Create(context.Background(), &user)
	require.Nil(s.T(), err)
	return user
}
func (s *TestUsersSuite) createRandomIdentity(user account.User, providerType string) account.Identity {
	profile := "foobarforupdate.com/" + uuid.NewV4().String() + "/" + user.ID.String()
	identity := account.Identity{
		Username:     "TestUpdateUserIntegration123" + uuid.NewV4().String(),
		ProviderType: providerType,
		ProfileURL:   &profile,
		User:         user,
		UserID:       account.NullUUID{UUID: user.ID, Valid: true},
	}
	err := s.identityRepo.Create(context.Background(), &identity)
	require.Nil(s.T(), err)
	return identity
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

func createUpdateUsersPayload(email, fullName, bio, imageURL, profileURL, company, username *string, registrationCompleted *bool, contextInformation map[string]interface{}) *app.UpdateUsersPayload {
	return &app.UpdateUsersPayload{
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

func createUpdateUsersPayloadWithoutContextInformation(email, fullName, bio, imageURL, profileURL *string) *app.UpdateUsersPayload {
	return &app.UpdateUsersPayload{
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

type dummyRemoteWITService struct{}

func (r *dummyRemoteWITService) UpdateWITUser(ctx context.Context, req *goa.RequestData, updatePayload *app.UpdateUsersPayload, witURL string, identityID string) error {
	return nil
}

func (r *dummyRemoteWITService) CreateWITUser(ctx context.Context, req *goa.RequestData, identity *account.Identity, witURL string, identityID string) error {
	return nil
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

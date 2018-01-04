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
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestUsersController(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &UsersControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type UsersControllerTestSuite struct {
	gormtestsupport.DBTestSuite
	svc            *goa.Service
	controller     *UsersController
	userRepo       account.UserRepository
	identityRepo   account.IdentityRepository
	profileService login.UserProfileService
	linkAPIService link.KeycloakIDPService
}

func (s *UsersControllerTestSuite) SetupSuite() {
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

func (s *UsersControllerTestSuite) SecuredController(identity account.Identity) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsUser("Users-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	controller.RemoteWITService = &dummyRemoteWITService{}
	return svc, controller
}

func (s *UsersControllerTestSuite) SecuredServiceAccountController(identity account.Identity) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsServiceAccountUser("Users-ServiceAccount-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	controller.RemoteWITService = &dummyRemoteWITService{}
	return svc, controller
}

// testing the utility function here, so we know it works ;)
func (s *UsersControllerTestSuite) TestCreateRandomUser() {

	s.T().Run("ok with defaults", func(t *testing.T) {
		// given
		user := s.createRandomUser("TestUpdateUserOK")
		identity := s.createRandomIdentity(user, account.KeycloakIDP)
		//when
		_, result := test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
		// then
		assert.Equal(t, identity.ID.String(), *result.Data.ID)
		assert.Equal(t, user.FullName, *result.Data.Attributes.FullName)
		assert.Equal(t, user.ImageURL, *result.Data.Attributes.ImageURL)
		assert.Equal(t, identity.ProviderType, *result.Data.Attributes.ProviderType)
		assert.Equal(t, identity.Username, *result.Data.Attributes.Username)
		assert.Equal(t, user.Company, *result.Data.Attributes.Company)
		assert.Nil(t, result.Data.Attributes.FeatureLevel)
	})

}
func (s *UsersControllerTestSuite) TestUpdateUser() {

	s.T().Run("ok", func(t *testing.T) {

		t.Run("ok", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserOK")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)

			// when
			newEmail := "TestUpdateUserOK-" + uuid.NewV4().String() + "@email.com"
			newFullName := "TestUpdateUserOK"
			newImageURL := "http://new.image.io/imageurl"
			newBio := "new bio"
			newProfileURL := "http://new.profile.url/url"
			newCompany := "updateCompany " + uuid.NewV4().String()
			newFeatureLevel := "beta"
			secureService, secureController := s.SecuredController(identity)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
				"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
				"rate":         100.00,
				"count":        3,
			}
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedEmail(newEmail),
				WithUpdatedFullName(newFullName),
				WithUpdatedBio(newBio),
				WithUpdatedImageURL(newImageURL),
				WithUpdatedURL(newProfileURL),
				WithUpdatedCompany(newCompany),
				WithUpdatedFeatureLevel(newFeatureLevel),
				WithUpdatedContextInformation(contextInformation))
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)

			// then
			require.NotNil(t, result)
			// let's fetch it and validate
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			assert.Equal(t, identity.ID.String(), *result.Data.ID)
			assert.Equal(t, newFullName, *result.Data.Attributes.FullName)
			assert.Equal(t, newImageURL, *result.Data.Attributes.ImageURL)
			assert.Equal(t, newBio, *result.Data.Attributes.Bio)
			assert.Equal(t, newProfileURL, *result.Data.Attributes.URL)
			assert.Equal(t, newCompany, *result.Data.Attributes.Company)
			require.NotNil(t, result.Data.Attributes.FeatureLevel)
			assert.Equal(t, newFeatureLevel, *result.Data.Attributes.FeatureLevel)

			updatedContextInformation := result.Data.Attributes.ContextInformation
			assert.Equal(t, contextInformation["last_visited"], updatedContextInformation["last_visited"])

			countValue, ok := updatedContextInformation["count"].(float64)
			assert.True(t, ok)
			assert.Equal(t, contextInformation["count"], int(countValue))
			assert.Equal(t, contextInformation["rate"], updatedContextInformation["rate"])
		})

		t.Run("add feature level", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserOK")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			// when
			newFeatureLevel := "beta"
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.NotNil(t, result)
			// let's fetch it and validate
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			require.NotNil(t, result.Data.Attributes.FeatureLevel)
			assert.Equal(t, newFeatureLevel, *result.Data.Attributes.FeatureLevel)
		})

		t.Run("internal level allowed", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserOK", WithEmailAddress("user@redhat.com"))
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			// when
			newFeatureLevel := "internal"
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.NotNil(t, result)
			// let's fetch it and validate
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			require.NotNil(t, result.Data.Attributes.FeatureLevel)
			assert.Equal(t, newFeatureLevel, *result.Data.Attributes.FeatureLevel)
		})

		t.Run("change feature level", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserOK", WithFeatureLevel("experimental"))
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			// when
			newFeatureLevel := "beta"
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)

			// then
			require.NotNil(t, result)
			// let's fetch it and validate
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			require.NotNil(t, result.Data.Attributes.FeatureLevel)
			assert.Equal(t, newFeatureLevel, *result.Data.Attributes.FeatureLevel)
		})

		t.Run("reset feature level", func(t *testing.T) {
			t.Run("with released value", func(t *testing.T) {
				user := s.createRandomUser("TestUpdateUserOK", WithFeatureLevel("experimental"))
				identity := s.createRandomIdentity(user, account.KeycloakIDP)
				// when
				newFeatureLevel := "released"
				secureService, secureController := s.SecuredController(identity)
				updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
				_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
				// then
				require.NotNil(t, result)
				// let's fetch it and validate
				_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
				require.NotNil(t, result)
				require.Nil(t, result.Data.Attributes.FeatureLevel)
			})
			t.Run("with empty value", func(t *testing.T) {
				user := s.createRandomUser("TestUpdateUserOK", WithFeatureLevel("experimental"))
				identity := s.createRandomIdentity(user, account.KeycloakIDP)
				// when
				newFeatureLevel := ""
				secureService, secureController := s.SecuredController(identity)
				updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
				_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
				// then
				require.NotNil(t, result)
				// let's fetch it and validate
				_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
				require.NotNil(t, result)
				require.Nil(t, result.Data.Attributes.FeatureLevel)
			})
		})

		t.Run("username multiple times ok", func(t *testing.T) {
			// given
			user := s.createRandomUser("OK")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			newUsername := identity.Username // new username = old userame
			secureService, secureController := s.SecuredController(identity)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}
			// when
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedUsername(newUsername),
				WithUpdatedContextInformation(contextInformation))
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.False(t, *result.Data.Attributes.RegistrationCompleted)
			// next attempt should PASS.
			_, result = test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			require.False(t, *result.Data.Attributes.RegistrationCompleted)
		})

		t.Run("registration completed ok", func(t *testing.T) {
			// given
			user := s.createRandomUser("OK")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			secureService, secureController := s.SecuredController(identity)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedContextInformation(contextInformation))
			// when
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.False(t, *result.Data.Attributes.RegistrationCompleted)
			// next attempt should PASS.
			updateUsersPayload = newUpdateUsersPayload(
				WithRegistrationCompleted(true),
				WithUpdatedContextInformation(contextInformation))
			test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("registration completed bad request", func(t *testing.T) {
			// given
			user := s.createRandomUser("OKRegCompleted")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			secureService, secureController := s.SecuredController(identity)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}
			// when
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedContextInformation(contextInformation))
			// then
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			require.False(t, *result.Data.Attributes.RegistrationCompleted)

			// next attempt should fail.
			updateUsersPayload = newUpdateUsersPayload(
				WithRegistrationCompleted(false),
				WithUpdatedContextInformation(contextInformation))
			test.UpdateUsersBadRequest(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("registration completed and username ok", func(t *testing.T) {
			// In this test case, we send both registrationCompleted=True and an updated username
			// as part of HTTP PATCH.
			user := s.createRandomUser("OKRegCompleted")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			secureService, secureController := s.SecuredController(identity)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}
			// when
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedContextInformation(contextInformation))
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.False(t, *result.Data.Attributes.RegistrationCompleted)
			newUsername := identity.Username + uuid.NewV4().String()
			updateUsersPayload = newUpdateUsersPayload(
				WithUpdatedUsername(newUsername),
				WithRegistrationCompleted(true),
				WithUpdatedContextInformation(contextInformation))

			test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("spaces in name", func(t *testing.T) {
			// given
			user := s.createRandomUser("OK")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			// when
			newEmail := "updated-" + uuid.NewV4().String() + "@email.com"

			// This is the special thing we are testing - everything else
			// has been tested in other tests.
			// We use the full name to derive the first and the last name
			// This test checks that the splitting is done correctly,
			// ie, the first word is the first name ,and the rest is the last name

			newFullName := " This name   has a   lot of spaces   in it"
			expectedFullName := "This name has a lot of spaces in it"
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
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedEmail(newEmail),
				WithUpdatedFullName(newFullName),
				WithUpdatedBio(newBio),
				WithUpdatedImageURL(newImageURL),
				WithUpdatedURL(newProfileURL),
				WithUpdatedCompany(newCompany),
				WithUpdatedContextInformation(contextInformation))

			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.NotNil(t, result)
			// let's fetch it and validate
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			assert.Equal(t, identity.ID.String(), *result.Data.ID)
			assert.Equal(t, expectedFullName, *result.Data.Attributes.FullName)
			assert.Equal(t, newImageURL, *result.Data.Attributes.ImageURL)
			assert.Equal(t, newBio, *result.Data.Attributes.Bio)
			assert.Equal(t, newProfileURL, *result.Data.Attributes.URL)
			assert.Equal(t, newCompany, *result.Data.Attributes.Company)

			updatedContextInformation := result.Data.Attributes.ContextInformation
			assert.Equal(t, contextInformation["last_visited"], updatedContextInformation["last_visited"])
			countValue, ok := updatedContextInformation["count"].(float64)
			assert.True(t, ok)
			assert.Equal(t, contextInformation["count"], int(countValue))
			assert.Equal(t, contextInformation["rate"], updatedContextInformation["rate"])
		})

		t.Run("unset variable in context information", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserUnsetVariableInContextInfo")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
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
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedEmail(newEmail),
				WithUpdatedFullName(newFullName),
				WithUpdatedBio(newBio),
				WithUpdatedImageURL(newImageURL),
				WithUpdatedURL(newProfileURL),
				WithUpdatedContextInformation(contextInformation))
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.NotNil(t, result)
			// let's fetch it and validate the usual stuff.
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			assert.Equal(t, identity.ID.String(), *result.Data.ID)
			assert.Equal(t, newFullName, *result.Data.Attributes.FullName)
			assert.Equal(t, newImageURL, *result.Data.Attributes.ImageURL)
			assert.Equal(t, newBio, *result.Data.Attributes.Bio)
			assert.Equal(t, newProfileURL, *result.Data.Attributes.URL)
			updatedContextInformation := result.Data.Attributes.ContextInformation
			assert.Equal(t, contextInformation["last_visited"], updatedContextInformation["last_visited"])
			// Usual stuff done, now lets unset
			contextInformation = map[string]interface{}{
				"last_visited": nil,
				"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
				"rate":         100.00,
				"count":        3,
			}
			updateUsersPayload = newUpdateUsersPayload(
				WithUpdatedEmail(newEmail),
				WithUpdatedFullName(newFullName),
				WithUpdatedBio(newBio),
				WithUpdatedImageURL(newImageURL),
				WithUpdatedURL(newProfileURL),
				WithUpdatedContextInformation(contextInformation))
			_, result = test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.NotNil(t, result)
			// let's fetch it and validate the usual stuff.
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			updatedContextInformation = result.Data.Attributes.ContextInformation

			// what was passed as non-nill should be intact.
			assert.Equal(t, contextInformation["space"], updatedContextInformation["space"])

			// what was pass as nil should not be found!
			_, ok := updatedContextInformation["last_visited"]
			assert.Equal(t, false, ok)
		})

		t.Run("without context info", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserOKWithoutContextInfo")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			// when
			newEmail := "TestUpdateUserOKWithoutContextInfo-" + uuid.NewV4().String() + "@email.com"
			newFullName := "TestUpdateUserOKWithoutContextInfo"
			newImageURL := "http://new.image.io/imageurl"
			newBio := "new bio"
			newProfileURL := "http://new.profile.url/url"
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedEmail(newEmail),
				WithUpdatedFullName(newFullName),
				WithUpdatedBio(newBio),
				WithUpdatedImageURL(newImageURL),
				WithUpdatedURL(newProfileURL))
			test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("patch content info", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestPatchUserContextInformation")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			// when
			secureService, secureController := s.SecuredController(identity)

			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
				"count":        3,
			}
			//secureController, secureService := createSecureController(t, identity)
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedContextInformation(contextInformation))

			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			// then
			require.NotNil(t, result)

			// let's fetch it and validate the usual stuff.
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			assert.Equal(t, identity.ID.String(), *result.Data.ID)
			updatedContextInformation := result.Data.Attributes.ContextInformation

			// Before we PATCH, ensure that the 1st time update has worked well.
			assert.Equal(t, contextInformation["last_visited"], updatedContextInformation["last_visited"])
			countValue, ok := updatedContextInformation["count"].(float64)
			assert.True(t, ok)
			assert.Equal(t, contextInformation["count"], int(countValue))

			// Usual stuff done, now lets PATCH only 1 contextInformation attribute
			patchedContextInformation := map[string]interface{}{
				"count": 5,
			}
			updateUsersPayload = newUpdateUsersPayload(WithUpdatedContextInformation(patchedContextInformation))
			_, result = test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
			require.NotNil(t, result)

			// let's fetch it and validate the usual stuff.
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			updatedContextInformation = result.Data.Attributes.ContextInformation

			// what was NOT passed, should remain intact.
			assert.Equal(t, contextInformation["last_visited"], updatedContextInformation["last_visited"])

			// what WAS PASSED, should be updated.
			countValue, ok = updatedContextInformation["count"].(float64)
			assert.True(t, ok)
			assert.Equal(t, patchedContextInformation["count"], int(countValue))
		})
	})

	s.T().Run("bad request", func(t *testing.T) {

		t.Run("invalid email address", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserOKWithoutContextInfo")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			// when
			newEmail := " "
			newFullName := "TestUpdateUserOKWithoutContextInfo"
			newImageURL := "http://new.image.io/imageurl"
			newBio := "new bio"
			newProfileURL := "http://new.profile.url/url"
			secureService, secureController := s.SecuredController(identity)

			//then
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedEmail(newEmail),
				WithUpdatedFullName(newFullName),
				WithUpdatedBio(newBio),
				WithUpdatedImageURL(newImageURL),
				WithUpdatedURL(newProfileURL))
			test.UpdateUsersBadRequest(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("invalid username", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserOKWithoutContextInfo")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
				"count":        3,
			}
			//when
			newUsername := " "
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedUsername(newUsername),
				WithUpdatedContextInformation(contextInformation))

			//then
			test.UpdateUsersBadRequest(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("existing username", func(t *testing.T) {
			// create 2 users.
			user := s.createRandomUser("OK")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			user2 := s.createRandomUser("OK2")
			identity2 := s.createRandomIdentity(user2, account.KeycloakIDP)

			// try updating using the username of an existing ( just created ) user.
			secureService, secureController := s.SecuredController(identity2)

			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}
			newUsername := identity.Username
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedUsername(newUsername),
				WithUpdatedContextInformation(contextInformation))

			test.UpdateUsersBadRequest(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("existing email", func(t *testing.T) {
			// create 2 users.
			user := s.createRandomUser("OK")
			s.createRandomIdentity(user, account.KeycloakIDP)
			user2 := s.createRandomUser("OK2")
			identity2 := s.createRandomIdentity(user2, account.KeycloakIDP)
			// try updating using the email of an existing ( just created ) user.
			secureService, secureController := s.SecuredController(identity2)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}
			newEmail := user.Email
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedEmail(newEmail),
				WithUpdatedContextInformation(contextInformation))
			test.UpdateUsersBadRequest(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

	})

	s.T().Run("forbidden", func(t *testing.T) {

		t.Run("username multiple times forbidden", func(t *testing.T) {
			user := s.createRandomUser("OK")
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			newUsername := identity.Username + uuid.NewV4().String()
			secureService, secureController := s.SecuredController(identity)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}

			// you can update username multiple times.
			// also omit registrationCompleted
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedUsername(newUsername),
				WithUpdatedContextInformation(contextInformation))

			test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)

			updateUsersPayload = newUpdateUsersPayload(
				WithUpdatedUsername(newUsername),
				WithRegistrationCompleted(true),
				WithUpdatedContextInformation(contextInformation))

			test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)

			// next attempt should fail.
			newUsername = identity.Username + uuid.NewV4().String()
			updateUsersPayload = newUpdateUsersPayload(
				WithUpdatedUsername(newUsername),
				WithUpdatedContextInformation(contextInformation))
			test.UpdateUsersForbidden(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("internal level for non-employee", func(t *testing.T) {
			// given
			user := s.createRandomUser("TestUpdateUserOK", WithEmailAddress("user@foo.com"))
			identity := s.createRandomIdentity(user, account.KeycloakIDP)
			// when/then
			newFeatureLevel := "internal"
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
			test.UpdateUsersForbidden(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})
	})

	s.T().Run("unauthorized", func(t *testing.T) {
		// given
		user := s.createRandomUser("TestUpdateUserUnauthorized")
		s.createRandomIdentity(user, account.KeycloakIDP)
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
		updateUsersPayload := newUpdateUsersPayload(
			WithUpdatedEmail(newEmail),
			WithUpdatedFullName(newFullName),
			WithUpdatedBio(newBio),
			WithUpdatedImageURL(newImageURL),
			WithUpdatedURL(newProfileURL),
			WithUpdatedContextInformation(contextInformation))

		// when/then
		test.UpdateUsersUnauthorized(s.T(), context.Background(), nil, s.controller, updateUsersPayload)
	})

}

func (s *UsersControllerTestSuite) TestShowUserOK() {
	// given user
	user := s.createRandomUser("TestShowUserOK")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	// when
	res, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	// then
	assertUser(s.T(), result.Data, user, identity)
	assertSingleUserResponseHeaders(s.T(), res, result, user)
}

func (s *UsersControllerTestSuite) TestShowUserOKUsingExpiredIfModifedSinceHeader() {
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

func (s *UsersControllerTestSuite) TestShowUserOKUsingExpiredIfNoneMatchHeader() {
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

func (s *UsersControllerTestSuite) TestShowUserNotModifiedUsingIfModifedSinceHeader() {
	// given user
	user := s.createRandomUser("TestShowUserNotModifiedUsingIfModifedSinceHeader")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	// when/then
	ifModifiedSince := app.ToHTTPTime(user.UpdatedAt.UTC())
	test.ShowUsersNotModified(s.T(), nil, nil, s.controller, identity.ID.String(), &ifModifiedSince, nil)
}

func (s *UsersControllerTestSuite) TestShowUserNotModifiedUsingIfNoneMatchHeader() {
	// given user
	user := s.createRandomUser("TestShowUserNotModifiedUsingIfNoneMatchHeader")
	identity := s.createRandomIdentity(user, account.KeycloakIDP)
	// when/then
	ifNoneMatch := app.GenerateEntityTag(user)
	test.ShowUsersNotModified(s.T(), nil, nil, s.controller, identity.ID.String(), nil, &ifNoneMatch)
}

func (s *UsersControllerTestSuite) TestShowUserNotFound() {
	// given user
	user := s.createRandomUser("TestShowUserNotFound")
	s.createRandomIdentity(user, account.KeycloakIDP)
	// when/then
	test.ShowUsersNotFound(s.T(), nil, nil, s.controller, uuid.NewV4().String(), nil, nil)
}

func (s *UsersControllerTestSuite) TestShowUserBadRequest() {
	// given user
	user := s.createRandomUser("TestShowUserBadRequest")
	s.createRandomIdentity(user, account.KeycloakIDP)
	// when/then
	test.ShowUsersBadRequest(s.T(), nil, nil, s.controller, "invaliduuid", nil, nil)
}

func (s *UsersControllerTestSuite) TestListUsersOK() {
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
func (s *UsersControllerTestSuite) TestListUsersWithMissingKeycloakIdentityOK() {
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

func (s *UsersControllerTestSuite) TestListUsersOKUsingExpiredIfModifiedSinceHeader() {
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

func (s *UsersControllerTestSuite) TestListUsersOKUsingExpiredIfNoneMatchHeader() {
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

func (s *UsersControllerTestSuite) TestListUsersNotModifiedUsingIfModifiedSinceHeader() {
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

func (s *UsersControllerTestSuite) TestListUsersByUsernameOK() {
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

func (s *UsersControllerTestSuite) TestListUsersByUsernameOKEmptyResult() {
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

func (s *UsersControllerTestSuite) TestListUsersByUsernameNotModifiedUsingIfNoneMatchHeader() {
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

func (s *UsersControllerTestSuite) TestListUsersByEmailOK() {
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

func (s *UsersControllerTestSuite) TestListUsersByEmailOKEmptyResult() {
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

func (s *UsersControllerTestSuite) TestListUsersByEmailNotModifiedUsingIfNoneMatchHeader() {
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

// a function to customize the generated `random` user
type CreateUserOption func(user *account.User)

func WithFeatureLevel(level string) CreateUserOption {
	return func(user *account.User) {
		user.FeatureLevel = &level
	}
}

func WithEmailAddress(email string) CreateUserOption {
	return func(user *account.User) {
		user.Email = email
	}
}

func (s *UsersControllerTestSuite) createRandomUser(fullname string, options ...CreateUserOption) account.User {
	user := account.User{
		Email:    uuid.NewV4().String() + "primaryForUpdat7e@example.com",
		FullName: fullname,
		ImageURL: "someURLForUpdate",
		ID:       uuid.NewV4(),
		Company:  uuid.NewV4().String() + "company",
		Cluster:  "My OSO cluster url",
	}
	for _, option := range options {
		option(&user)
	}

	err := s.userRepo.Create(context.Background(), &user)
	require.Nil(s.T(), err)
	return user
}
func (s *UsersControllerTestSuite) createRandomIdentity(user account.User, providerType string) account.Identity {
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
	assert.Equal(t, expectedUser.Email, *actual.Attributes.Email)
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

type UpdateUserOption func(attrs *app.UpdateIdentityDataAttributes)

func WithUpdatedEmail(email string) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.Email = &email
	}
}

func WithUpdatedFullName(fullName string) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.FullName = &fullName
	}
}

func WithUpdatedUsername(username string) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.Username = &username
	}
}

func WithUpdatedBio(bio string) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.Bio = &bio
	}
}

func WithUpdatedImageURL(imageURL string) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.ImageURL = &imageURL
	}
}

func WithUpdatedURL(url string) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.URL = &url
	}
}

func WithUpdatedCompany(company string) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.Company = &company
	}
}

func WithUpdatedFeatureLevel(featureLevel string) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.FeatureLevel = &featureLevel
	}
}

func WithUpdatedContextInformation(contextInformation map[string]interface{}) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.ContextInformation = contextInformation
	}
}

func WithRegistrationCompleted(registrationCompleted bool) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.RegistrationCompleted = &registrationCompleted
	}
}

func newUpdateUsersPayload(updateOptions ...UpdateUserOption) *app.UpdateUsersPayload {
	attributes := app.UpdateIdentityDataAttributes{}
	for _, option := range updateOptions {
		option(&attributes)
	}
	return &app.UpdateUsersPayload{
		Data: &app.UpdateUserData{
			Type:       "identities",
			Attributes: &attributes,
		},
	}
}

func getUserUpdatedAt(appUser app.User) time.Time {
	return appUser.Data.Attributes.UpdatedAt.Truncate(time.Second).UTC()
}

func (s *UsersControllerTestSuite) generateUsersTag(allUsers app.UserArray) string {
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

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountWithAllFieldsOK() {

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

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountForExistingUserInDbFails() {
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

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountWithRequiredFieldsOnlyOK() {
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

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountWithMissingRequiredFieldsFails() {
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

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountUnauthorized() {
	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestIdentity)

	// then
	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, nil, &user.Cluster, &identity.RegistrationCompleted, nil, user.ContextInformation)
	test.CreateUsersUnauthorized(s.T(), secureService.Context, secureService, secureController, createUserPayload)
}

func (s *UsersControllerTestSuite) TestCreateUserAsNonServiceAccountUnauthorized() {
	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity

	secureService, secureController := s.SecuredController(testsupport.TestIdentity)

	// then
	createUserPayload := createCreateUsersAsServiceAccountPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, nil, &user.Cluster, &identity.RegistrationCompleted, nil, user.ContextInformation)
	test.CreateUsersUnauthorized(s.T(), secureService.Context, secureService, secureController, createUserPayload)
}

func (s *UsersControllerTestSuite) TestCreateUserUnauthorized() {
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

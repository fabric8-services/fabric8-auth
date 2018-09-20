package controller_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	accountrepo "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/account/service"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/app/test"
	"github.com/fabric8-services/fabric8-auth/application/service/factory"
	. "github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
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

func TestUsersController(t *testing.T) {
	resource.Require(t, resource.Database)
	suite.Run(t, &UsersControllerTestSuite{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

type UsersControllerTestSuite struct {
	gormtestsupport.DBTestSuite
	svc            *goa.Service
	controller     *UsersController
	userRepo       accountrepo.UserRepository
	identityRepo   accountrepo.IdentityRepository
	profileService login.UserProfileService
	linkAPIService link.KeycloakIDPService
	tenantService  *dummyTenantService
}

func (s *UsersControllerTestSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()
	s.svc = goa.New("test")
	testAttributeValue := "a"
	dummyProfileResponse := createDummyUserProfileResponse(&testAttributeValue, &testAttributeValue, &testAttributeValue)
	keycloakUserProfileService := newDummyUserProfileService(dummyProfileResponse)
	s.profileService = keycloakUserProfileService
	s.linkAPIService = &dummyKeycloakLinkService{}
	witServiceMock := testsupport.NewWITMock(s.T(), uuid.NewV4().String(), "test-space")
	s.Application = gormapplication.NewGormDB(s.DB, s.Configuration, factory.WithWITService(witServiceMock))
	s.controller = NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	s.userRepo = s.Application.Users()
	s.identityRepo = s.Application.Identities()
	s.tenantService = &dummyTenantService{}
}

func (s *UsersControllerTestSuite) UnsecuredController() (*goa.Service, *UsersController) {
	svc := testsupport.UnsecuredService("Users-Service")
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	controller.EmailVerificationService = service.NewEmailVerificationClient(s.Application)
	return svc, controller
}

func (s *UsersControllerTestSuite) UnsecuredControllerDeprovisionedUser() (*goa.Service, *UsersController) {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, uuid.NewV4().String())
	require.Nil(s.T(), err)

	svc := testsupport.ServiceAsUser("Users-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	controller.EmailVerificationService = service.NewEmailVerificationClient(s.Application)
	return svc, controller
}

func (s *UsersControllerTestSuite) SecuredController(identity accountrepo.Identity) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsUser("Users-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	controller.EmailVerificationService = service.NewEmailVerificationClient(s.Application)
	return svc, controller
}

func (s *UsersControllerTestSuite) SecuredControllerWithDummyEmailService(identity accountrepo.Identity, emailSuccess bool) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsUser("Users-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	controller.EmailVerificationService = &DummyEmailVerificationService{success: emailSuccess}
	return svc, controller
}

func (s *UsersControllerTestSuite) SecuredServiceAccountController(identity accountrepo.Identity) (*goa.Service, *UsersController) {
	svc := testsupport.ServiceAsServiceAccountUser("Users-ServiceAccount-Service", identity)
	controller := NewUsersController(s.svc, s.Application, s.Configuration, s.profileService, s.linkAPIService)
	return svc, controller
}

// testing the utility function here, so we know it works ;)
func (s *UsersControllerTestSuite) TestCreateRandomUser() {

	s.T().Run("ok with defaults", func(t *testing.T) {
		// given
		user, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
		//when
		_, result := test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
		// then
		assert.Equal(t, identity.ID.String(), *result.Data.ID)
		assert.Equal(t, user.FullName, *result.Data.Attributes.FullName)
		assert.Equal(t, user.ImageURL, *result.Data.Attributes.ImageURL)
		assert.Equal(t, identity.ProviderType, *result.Data.Attributes.ProviderType)
		assert.Equal(t, identity.Username, *result.Data.Attributes.Username)
		assert.Equal(t, user.Company, *result.Data.Attributes.Company)
		assert.Equal(t, accountrepo.DefaultFeatureLevel, *result.Data.Attributes.FeatureLevel)
	})
}

func (s *UsersControllerTestSuite) updateDeprovisionedAttribute(deprovisioned bool) {
	var identity accountrepo.Identity
	var err error
	if deprovisioned {
		_, identity = s.createRandomUserIdentity(s.T(), "tes-updateDeprovisionedAttribute")
	} else {
		identity, err = testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "test-updateDeprovisionedAttribute")
		require.NoError(s.T(), err)
	}
	secureService, secureController := s.SecuredController(identity)
	updateUsersPayload := &app.UpdateUsersPayload{
		Data: &app.UpdateUserData{
			Attributes: &app.UpdateIdentityDataAttributes{Deprovisioned: &deprovisioned},
			Type:       "identities",
		},
	}
	// Try to deprovision
	if deprovisioned {
		// in this case, the existing state is that the user is not deprovisioned.
		test.UpdateUsersOK(s.T(), secureService.Context, secureService, secureController, updateUsersPayload)
		s.checkIfUserDeprovisioned(identity.ID, !deprovisioned)
	} else {
		// in this case, the existing state is that the user is deprovisioned.
		test.UpdateUsersUnauthorized(s.T(), secureController.Context, secureService, secureController, updateUsersPayload)
		s.checkIfUserDeprovisioned(identity.ID, !deprovisioned)
	}
}

func (s *UsersControllerTestSuite) TestUpdateUser() {

	s.T().Run("ok", func(t *testing.T) {

		t.Run("ok", func(t *testing.T) {
			// given
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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

		t.Run("deprovisioned attribute ignored", func(t *testing.T) {
			s.updateDeprovisionedAttribute(true)
			s.updateDeprovisionedAttribute(false)
		})

		t.Run("add feature level", func(t *testing.T) {
			// given
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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

		t.Run("change feature level", func(t *testing.T) {
			t.Run("internal level allowed", func(t *testing.T) {
				t.Run("allowed", func(t *testing.T) {
					// given
					_, identity := s.createRandomUserIdentity(t, "TestUpdateUser", WithEmailAddress(uuid.NewV4().String()+"user@redhat.com"), WithEmailAddressVerified(true))
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
				t.Run("not allowed", func(t *testing.T) {
					// given non internal user
					_, identity := s.createRandomUserIdentity(t, "TestUpdateUser", WithEmailAddress(uuid.NewV4().String()+"user@foo.com"), WithEmailAddressVerified(true))
					// when
					newFeatureLevel := "internal"
					secureService, secureController := s.SecuredController(identity)
					updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
					test.UpdateUsersForbidden(t, secureService.Context, secureService, secureController, updateUsersPayload)
				})
			})
			// other levels
			for _, level := range []string{"experimental", "beta", "released"} {
				t.Run(level, func(t *testing.T) {
					// given
					_, identity := s.createRandomUserIdentity(t, "TestUpdateUser", WithFeatureLevel("experimental"))
					// when
					secureService, secureController := s.SecuredController(identity)
					updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(level))
					_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)

					// then
					require.NotNil(t, result)
					// let's fetch it and validate
					_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
					require.NotNil(t, result)
					require.NotNil(t, result.Data.Attributes.FeatureLevel)
					assert.Equal(t, level, *result.Data.Attributes.FeatureLevel)
				})
			}
		})

		t.Run("do not change feature level", func(t *testing.T) {
			// given
			currentFeatureLevel := "experimental"
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser", WithFeatureLevel(currentFeatureLevel))
			// when
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(WithRegistrationCompleted(true))
			_, result := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)

			// then
			require.NotNil(t, result)
			// let's fetch it and validate
			_, result = test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)
			require.NotNil(t, result)
			assert.Equal(t, currentFeatureLevel, *result.Data.Attributes.FeatureLevel)
		})

		t.Run("username multiple times ok", func(t *testing.T) {
			// given
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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

		t.Run("patch context info", func(t *testing.T) {
			// given
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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

		t.Run("view hidden email address", func(t *testing.T) {
			// given user1
			user, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
			secureService, secureController := s.SecuredController(identity)
			// when
			email := user.Email
			// by default, email is public.
			_, result := test.ListUsersOK(t, nil, nil, s.controller, &email, nil, nil, nil)
			returnedUser := result.Data[0].Attributes
			require.Equal(t, email, *returnedUser.Email)
			require.False(t, *returnedUser.EmailPrivate)

			// check for /api/users/<ID>
			// should show public email when not made private.
			_, singleResult := test.ShowUsersOK(t, secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
			returnedUser = singleResult.Data.Attributes
			require.Equal(t, email, *returnedUser.Email)
			require.False(t, *returnedUser.EmailPrivate)

			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
				"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
				"rate":         100.00,
				"count":        3,
			}
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedContextInformation(contextInformation), WithUpdatedEmailPrivate(true))
			test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)

			// the /api/users/<ID> endpoint should hide out the email.
			_, showUserResponse := test.ShowUsersOK(t, secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
			require.NotEqual(t, user.Email, *showUserResponse.Data.Attributes.Email)
			require.Equal(t, "", *showUserResponse.Data.Attributes.Email)
			require.True(t, *showUserResponse.Data.Attributes.EmailPrivate)

			// On using the notification service account token, email would magically show up.
			secureService, secureController = s.SecuredServiceAccountController(testsupport.TestNotificationIdentity)
			_, showUserResponse = test.ShowUsersOK(t, secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
			require.Equal(t, user.Email, *showUserResponse.Data.Attributes.Email)
			require.True(t, *showUserResponse.Data.Attributes.EmailPrivate)

			// On using the tenant service account token, email would magically show up too.
			secureService, secureController = s.SecuredServiceAccountController(testsupport.TestTenantIdentity)
			_, showUserResponse = test.ShowUsersOK(t, secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
			require.Equal(t, user.Email, *showUserResponse.Data.Attributes.Email)
			require.True(t, *showUserResponse.Data.Attributes.EmailPrivate)

			// On using the online-registration service account token, email would NOT show up.
			secureService, secureController = s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)
			_, showUserResponse = test.ShowUsersOK(t, secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
			require.NotEqual(t, user.Email, *showUserResponse.Data.Attributes.Email)
			require.Equal(t, "", *showUserResponse.Data.Attributes.Email)
			require.True(t, *showUserResponse.Data.Attributes.EmailPrivate)

		})

		t.Run("hide email address", func(t *testing.T) {
			// given user1
			user, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
			secureService, secureController := s.SecuredController(identity)
			// when
			email := user.Email
			// by default, email is public.
			_, result := test.ListUsersOK(t, nil, nil, s.controller, &email, nil, nil, nil)
			returnedUser := result.Data[0].Attributes
			require.Equal(t, email, *returnedUser.Email)
			require.False(t, *returnedUser.EmailPrivate)

			// check for /api/users/<ID>
			// should show public email when not made private.
			_, singleResult := test.ShowUsersOK(t, secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
			returnedUser = singleResult.Data.Attributes
			require.Equal(t, email, *returnedUser.Email)
			require.False(t, *returnedUser.EmailPrivate)

			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
				"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
				"rate":         100.00,
				"count":        3,
			}
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedContextInformation(contextInformation), WithUpdatedEmailPrivate(true))
			_, updateResult := test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)

			// Email will be visible to the one who it belongs to
			require.True(t, *updateResult.Data.Attributes.EmailPrivate)
			require.Equal(t, user.Email, *updateResult.Data.Attributes.Email)

			// But when you try to access the same with an API which doesn't respect auth,
			// it wouldn't be visible.
			_, result = test.ListUsersOK(t, nil, nil, s.controller, &email, nil, nil, nil)
			require.Empty(t, result.Data)

			// the /api/users/<ID> endpoint should also hide out the email.
			_, showUserResponse := test.ShowUsersOK(t, secureService.Context, secureService, s.controller, identity.ID.String(), nil, nil)
			require.NotEqual(t, user.Email, *showUserResponse.Data.Attributes.Email)
			require.Equal(t, "", *showUserResponse.Data.Attributes.Email)
			require.True(t, *showUserResponse.Data.Attributes.EmailPrivate)
		})
	})

	s.T().Run("bad request", func(t *testing.T) {

		t.Run("invalid email address", func(t *testing.T) {
			// given
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
			// when/then
			newEmail := " "
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
			test.UpdateUsersBadRequest(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("invalid username", func(t *testing.T) {
			// given
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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
			_, identity1 := s.createRandomUserIdentity(t, "TestUpdateUser")
			_, identity2 := s.createRandomUserIdentity(t, "TestUpdateUser")

			// try updating using the username of an existing ( just created ) user.
			secureService, secureController := s.SecuredController(identity2)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}
			newUsername := identity1.Username
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedUsername(newUsername),
				WithUpdatedContextInformation(contextInformation))
			test.UpdateUsersBadRequest(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("existing email", func(t *testing.T) {
			// create 2 users.
			// user1, identity1 := s.createRandomUserIdentity(t, "TestUpdateUser")
			user1, _ := s.createRandomUserIdentity(t, "TestUpdateUser")
			_, identity2 := s.createRandomUserIdentity(t, "TestUpdateUser")
			// try updating using the email of an existing ( just created ) user.
			secureService, secureController := s.SecuredController(identity2)
			contextInformation := map[string]interface{}{
				"last_visited": "yesterday",
			}
			newEmail := user1.Email
			updateUsersPayload := newUpdateUsersPayload(
				WithUpdatedEmail(newEmail),
				WithUpdatedContextInformation(contextInformation))
			test.UpdateUsersBadRequest(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

	})

	s.T().Run("forbidden", func(t *testing.T) {

		t.Run("username multiple times forbidden", func(t *testing.T) {
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser")
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
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser", WithEmailAddress(fmt.Sprintf("%s@foo.com", uuid.NewV4())), WithEmailAddressVerified(true))
			// when/then
			newFeatureLevel := "internal"
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
			test.UpdateUsersForbidden(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})

		t.Run("internal level for non-verified employee", func(t *testing.T) {
			// given
			_, identity := s.createRandomUserIdentity(t, "TestUpdateUser", WithEmailAddress(fmt.Sprintf("%s@redhat.com", uuid.NewV4())), WithEmailAddressVerified(false))
			// when/then
			newFeatureLevel := "internal"
			secureService, secureController := s.SecuredController(identity)
			updateUsersPayload := newUpdateUsersPayload(WithUpdatedFeatureLevel(newFeatureLevel))
			test.UpdateUsersForbidden(t, secureService.Context, secureService, secureController, updateUsersPayload)
		})
	})

	s.T().Run("unauthorized", func(t *testing.T) {
		// given
		s.createRandomUserIdentity(t, "TestUpdateUser")
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
		test.UpdateUsersUnauthorized(t, context.Background(), nil, s.controller, updateUsersPayload)
	})

	s.T().Run("deprovisioned user cannot update user", func(t *testing.T) {
		// given
		svc, ctrl := s.UnsecuredControllerDeprovisionedUser()
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
		test.UpdateUsersUnauthorized(t, ctrl.Context, svc, ctrl, updateUsersPayload)
	})

}

func (s *UsersControllerTestSuite) checkIfUserDeprovisioned(id uuid.UUID, expected bool) {
	identityRepository := accountrepo.NewIdentityRepository(s.DB)
	identity, err := identityRepository.LoadWithUser(context.Background(), id)
	require.NoError(s.T(), err)
	require.Equal(s.T(), expected, identity.User.Deprovisioned)
}

func (s *UsersControllerTestSuite) TestSendEmailVerificationCode() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		_, identity := s.createRandomUserIdentity(t, "TestSendEmailVerificationCode-OK")
		test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)

		// when
		secureService, secureController := s.SecuredControllerWithDummyEmailService(identity, true)
		test.SendEmailVerificationCodeUsersNoContent(t, secureService.Context, secureService, secureController)

	})

	s.T().Run("unauthorized when unknown identity in context", func(t *testing.T) {
		// given
		identity := testsupport.TestIdentity2

		// when
		secureService, secureController := s.SecuredControllerWithDummyEmailService(identity, true)
		test.SendEmailVerificationCodeUsersUnauthorized(t, secureService.Context, secureService, secureController)
	})

	s.T().Run("unauthorized when no identity in context", func(t *testing.T) {
		service, controller := s.UnsecuredController()
		test.SendEmailVerificationCodeUsersUnauthorized(t, service.Context, service, controller)
	})

	s.T().Run("email failure", func(t *testing.T) {
		// given
		_, identity := s.createRandomUserIdentity(t, "TestSendEmailVerificationCode-EmailFailure")
		test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)

		// when
		secureService, secureController := s.SecuredControllerWithDummyEmailService(identity, false)
		test.SendEmailVerificationCodeUsersInternalServerError(t, secureService.Context, secureService, secureController)
	})
}

func (s *UsersControllerTestSuite) TestVerifyEmail() {

	s.T().Run("ok", func(t *testing.T) {
		// given
		user, identity := s.createRandomUserIdentity(t, "TestVerifyEmailOK")
		test.ShowUsersOK(t, nil, nil, s.controller, identity.ID.String(), nil, nil)

		// when
		secureService, secureController := s.SecuredController(identity)
		updateUsersPayload := newUpdateUsersPayload(
			WithUpdatedEmail("TestUpdateUserOK-"+uuid.NewV4().String()+"@email.com"),
			WithUpdatedFullName("TestUpdateUserOK"),
			WithUpdatedBio("new bio"),
			WithUpdatedImageURL("http://new.image.io/imageurl"),
			WithUpdatedURL("http://new.profile.url/url"),
			WithUpdatedCompany("updateCompany "+uuid.NewV4().String()),
			WithUpdatedContextInformation(map[string]interface{}{
				"last_visited": "yesterday",
				"space":        "3d6dab8d-f204-42e8-ab29-cdb1c93130ad",
				"rate":         100.00,
				"count":        3,
			}))
		test.UpdateUsersOK(t, secureService.Context, secureService, secureController, updateUsersPayload)
		// then
		codes, err := s.Application.VerificationCodes().Query(accountrepo.VerificationCodeWithUser(), accountrepo.VerificationCodeFilterByUserID(user.ID))
		require.NoError(t, err)
		require.Len(t, codes, 1)
		verificationCode := codes[0].Code

		rw := test.VerifyEmailUsersTemporaryRedirect(t, secureService.Context, secureService, secureController, verificationCode)
		redirectLocation := rw.Header().Get("Location")
		assert.Equal(t, "https://prod-preview.openshift.io/_home?verified=true", redirectLocation)

		codes, err = s.Application.VerificationCodes().Query(accountrepo.VerificationCodeWithUser(), accountrepo.VerificationCodeFilterByUserID(user.ID))
		require.NoError(t, err)
		require.Len(t, codes, 0)
	})

	s.T().Run("fail", func(t *testing.T) {
		// given
		_, identity := s.createRandomUserIdentity(t, "TestVerifyEmailFail")
		// when
		secureService, secureController := s.SecuredController(identity)
		rw := test.VerifyEmailUsersTemporaryRedirect(t, secureService.Context, secureService, secureController, "ABCD")
		redirectLocation := rw.Header().Get("Location")
		testsupport.EqualURLs(t, "https://prod-preview.openshift.io/_home?verified=false&error=code+with+id+%27ABCD%27+not+found", redirectLocation)
	})
}

func (s *UsersControllerTestSuite) TestShowUserOK() {
	// given user
	user, identity := s.createRandomUserIdentity(s.T(), "TestShowUserOK")
	// when
	res, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	// then
	assertUser(s.T(), result.Data, user, identity)
	assertSingleUserResponseHeaders(s.T(), res, result, user)
}

func (s *UsersControllerTestSuite) TestShowDeprovisionedUsersFails() {
	identity, err := testsupport.CreateDeprovisionedTestIdentityAndUser(s.DB, "TestShowDeprovisionedUsersFails"+uuid.NewV4().String())
	require.NoError(s.T(), err)

	// User returned if no token present
	_, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	assertUser(s.T(), result.Data, identity.User, identity)

	// Still can get the user if called by the Notification Service
	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestNotificationIdentity)
	_, result = test.ShowUsersOK(s.T(), secureService.Context, secureService, secureController, identity.ID.String(), nil, nil)
	assertUser(s.T(), result.Data, identity.User, identity)

	// Get 401 if called by the Tenant Service
	secureService, secureController = s.SecuredServiceAccountController(testsupport.TestTenantIdentity)
	rw, _ := test.ShowUsersUnauthorized(s.T(), secureService.Context, secureService, secureController, identity.ID.String(), nil, nil)

	assert.Equal(s.T(), "DEPROVISIONED description=\"Account has been deprovisioned\"", rw.Header().Get("WWW-Authenticate"))
	assert.Contains(s.T(), "WWW-Authenticate", rw.Header().Get("Access-Control-Expose-Headers"))
}

func (s *UsersControllerTestSuite) TestShowUserOKUsingExpiredIfModifedSinceHeader() {
	// given user
	user, identity := s.createRandomUserIdentity(s.T(), "TestShowUserOKUsingExpiredIfModifedSinceHeader")
	// when
	ifModifiedSince := app.ToHTTPTime(user.UpdatedAt.Add(-1 * time.Hour))
	res, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), &ifModifiedSince, nil)
	// then
	assertUser(s.T(), result.Data, user, identity)
	assertSingleUserResponseHeaders(s.T(), res, result, user)
}

func (s *UsersControllerTestSuite) TestShowUserOKUsingExpiredIfNoneMatchHeader() {
	// given user
	user, identity := s.createRandomUserIdentity(s.T(), "TestShowUserOKUsingExpiredIfNoneMatchHeader")
	// when
	ifNoneMatch := "foo"
	res, result := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, &ifNoneMatch)
	// then
	assertUser(s.T(), result.Data, user, identity)
	assertSingleUserResponseHeaders(s.T(), res, result, user)
}

func (s *UsersControllerTestSuite) TestShowUserNotModifiedUsingIfModifedSinceHeader() {
	// given user
	_, identity := s.createRandomUserIdentity(s.T(), "TestShowUserNotModifiedUsingIfModifedSinceHeader")
	res, _ := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	lastModified, err := getHeader(res, app.LastModified)
	require.NoError(s.T(), err)
	// when/then
	test.ShowUsersNotModified(s.T(), nil, nil, s.controller, identity.ID.String(), lastModified, nil)
}

func (s *UsersControllerTestSuite) TestShowUserNotModifiedUsingIfNoneMatchHeader() {
	// given user
	_, identity := s.createRandomUserIdentity(s.T(), "TestShowUserNotModifiedUsingIfNoneMatchHeader")
	res, _ := test.ShowUsersOK(s.T(), nil, nil, s.controller, identity.ID.String(), nil, nil)
	etag, err := getHeader(res, app.ETag)
	require.NoError(s.T(), err)
	// when/then
	test.ShowUsersNotModified(s.T(), nil, nil, s.controller, identity.ID.String(), nil, etag)
}

func (s *UsersControllerTestSuite) TestShowUserNotFound() {
	// given user
	s.createRandomUserIdentity(s.T(), "TestShowUserNotFound")
	// when/then
	test.ShowUsersNotFound(s.T(), nil, nil, s.controller, uuid.NewV4().String(), nil, nil)
}

func (s *UsersControllerTestSuite) TestShowUserBadRequest() {
	// given user
	s.createRandomUserIdentity(s.T(), "TestShowUserBadRequest")
	// when/then
	test.ShowUsersBadRequest(s.T(), nil, nil, s.controller, "invaliduuid", nil, nil)
}

func (s *UsersControllerTestSuite) TestListUsersOK() {
	// given user1
	user1, identity1 := s.createRandomUserIdentity(s.T(), "TestListUsersOK1")
	// given user2
	user2, identity2 := s.createRandomUserIdentity(s.T(), "TestListUsersOK2")
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
	_, identity1 := s.createRandomUserIdentity(s.T(), "TestListUsersOK1")
	identity1.ProviderType = ""
	err := s.Application.Identities().Save(context.Background(), &identity1)
	require.NoError(s.T(), err)
	// given user2
	user2, identity2 := s.createRandomUserIdentity(s.T(), "TestListUsersOK2")
	// when
	res, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity2.Username, nil, nil)
	// then
	assertUser(s.T(), findUser(identity2.ID, result.Data), user2, identity2)
	assertMultiUsersResponseHeaders(s.T(), res, user2)
}

func (s *UsersControllerTestSuite) TestListUsersOKUsingExpiredIfModifiedSinceHeader() {
	// given user1
	user1, identity1 := s.createRandomUserIdentity(s.T(), "TestListUsersOKUsingExpiredIfModifiedSinceHeader")
	// given user2
	user2, identity2 := s.createRandomUserIdentity(s.T(), "TestListUsersOKUsingExpiredIfModifiedSinceHeader2")
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
	user1, identity1 := s.createRandomUserIdentity(s.T(), "TestListUsersOKUsingExpiredIfNoneMatchHeader")
	// given user2
	user2, identity2 := s.createRandomUserIdentity(s.T(), "TestListUsersOKUsingExpiredIfNoneMatchHeader2")
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
	// given user
	s.createRandomUserIdentity(s.T(), "TestListUsersNotModifiedUsingIfModifiedSinceHeader2")
	res, _ := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, nil, nil, nil)
	lastModified, err := getHeader(res, app.LastModified)
	require.NoError(s.T(), err)
	// when
	res = test.ListUsersNotModified(s.T(), nil, nil, s.controller, nil, nil, lastModified, nil)
	// then
	assertResponseHeaders(s.T(), res)
}

func (s *UsersControllerTestSuite) TestListUsersByUsernameOK() {
	// given user1
	user1, identity1 := s.createRandomUserIdentity(s.T(), "TestListUsersOK1")
	s.createRandomUserIdentity(s.T(), "TestListUsersOK2") // other unused users, will not appear in list result
	s.createRandomUserIdentity(s.T(), "TestListUsersOK3")
	// when
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity1.Username, nil, nil)
	// then
	for i, data := range result.Data {
		s.T().Log(fmt.Sprintf("Result #%d: %s %v", i, *data.ID, *data.Attributes.Username))
	}
	require.Len(s.T(), result.Data, 1)
	assertUser(s.T(), findUser(identity1.ID, result.Data), user1, identity1)
}

func (s *UsersControllerTestSuite) TestListUsersByUsernameOKEmptyResult() {
	// given user1
	s.createRandomUserIdentity(s.T(), "TestListUsersOK1")
	// given user2
	s.createRandomUserIdentity(s.T(), "TestListUsersOK2")
	// when
	username := "foobar"
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &username, nil, nil)
	// then
	require.Len(s.T(), result.Data, 0)
}

func (s *UsersControllerTestSuite) TestListUsersByUsernameNotModifiedUsingIfNoneMatchHeader() {
	// given user1
	_, identity := s.createRandomUserIdentity(s.T(), "TestListUsersOK1")
	res, _ := test.ListUsersOK(s.T(), nil, nil, s.controller, nil, &identity.Username, nil, nil)
	etag, err := getHeader(res, app.ETag)
	require.NoError(s.T(), err)
	// when
	res = test.ListUsersNotModified(s.T(), nil, nil, s.controller, nil, &identity.Username, nil, etag)
	// then
	assertResponseHeaders(s.T(), res)
}

func (s *UsersControllerTestSuite) TestListUsersByEmailOK() {
	// given user1
	user1, identity1 := s.createRandomUserIdentity(s.T(), "TestListUsersOK1")
	// given user2
	s.createRandomUserIdentity(s.T(), "TestListUsersOK2")
	// when
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, &user1.Email, nil, nil, nil)
	// then
	for i, data := range result.Data {
		s.T().Log(fmt.Sprintf("Result #%d: %s %v", i, *data.ID, *data.Attributes.Username))
	}
	// even though 2 identites were created, only 1 app user was returned.
	// this is because only we currently consider only kc identites.
	require.Len(s.T(), result.Data, 1)
	assertUser(s.T(), findUser(identity1.ID, result.Data), user1, identity1)
}

func (s *UsersControllerTestSuite) TestListUsersByEmailOKEmptyResult() {
	// given user1
	s.createRandomUserIdentity(s.T(), "TestListUsersOK1")
	// given user2
	s.createRandomUserIdentity(s.T(), "TestListUsersOK2")
	// when
	email := "foo@bar.com"
	_, result := test.ListUsersOK(s.T(), nil, nil, s.controller, &email, nil, nil, nil)
	// then
	require.Len(s.T(), result.Data, 0)
}

func (s *UsersControllerTestSuite) TestListUsersByEmailNotModifiedUsingIfNoneMatchHeader() {
	// given user1
	user1, _ := s.createRandomUserIdentity(s.T(), "TestListUsersOK1")
	// given user2
	s.createRandomUserIdentity(s.T(), "TestListUsersOK2")
	res, _ := test.ListUsersOK(s.T(), nil, nil, s.controller, &user1.Email, nil, nil, nil)
	etag, err := getHeader(res, app.ETag)
	require.NoError(s.T(), err)
	// when
	res = test.ListUsersNotModified(s.T(), nil, nil, s.controller, &user1.Email, nil, nil, etag)
	// then
	assertResponseHeaders(s.T(), res)
}

// a function to customize the generated `random` user
type CreateUserOption func(user *accountrepo.User)

func WithFeatureLevel(level string) CreateUserOption {
	return func(user *accountrepo.User) {
		user.FeatureLevel = level
	}
}

func WithEmailAddress(email string) CreateUserOption {
	return func(user *accountrepo.User) {
		user.Email = email
	}
}

func WithEmailAddressVerified(verified bool) CreateUserOption {
	return func(user *accountrepo.User) {
		user.EmailVerified = verified
	}
}

func (s *UsersControllerTestSuite) createRandomUserIdentity(t *testing.T, fullname string, options ...CreateUserOption) (accountrepo.User, accountrepo.Identity) {
	user := accountrepo.User{
		Email:        uuid.NewV4().String() + "primaryForUpdat7e@example.com",
		FullName:     fullname,
		ImageURL:     "someURLForUpdate",
		ID:           uuid.NewV4(),
		Company:      uuid.NewV4().String() + "company",
		Cluster:      "https://api.openshift.com",
		EmailPrivate: false,                           // being explicit
		FeatureLevel: accountrepo.DefaultFeatureLevel, // being explicit
	}
	for _, option := range options {
		option(&user)
	}
	identity, err := testsupport.CreateTestUser(s.DB, &user)
	require.NoError(t, err)
	return user, identity
}

func findUser(id uuid.UUID, userData []*app.UserData) *app.UserData {
	for _, user := range userData {
		if *user.ID == id.String() {
			return user
		}
	}
	return nil
}

func assertCreatedUser(t *testing.T, actual *app.UserData, expectedUser accountrepo.User, expectedIdentity accountrepo.Identity) {
	require.NotNil(t, actual)
	assert.Equal(t, expectedIdentity.Username, *actual.Attributes.Username)
	if expectedIdentity.ProviderType == "" {
		assert.Equal(t, accountrepo.KeycloakIDP, *actual.Attributes.ProviderType)
	} else {
		assert.Equal(t, expectedIdentity.ProviderType, *actual.Attributes.ProviderType)
	}
	assert.Equal(t, false, *actual.Attributes.RegistrationCompleted)
	assert.Equal(t, expectedUser.FullName, *actual.Attributes.FullName)
	assert.Equal(t, expectedUser.ImageURL, *actual.Attributes.ImageURL)
	assert.Equal(t, expectedUser.Email, *actual.Attributes.Email)
	assert.Equal(t, expectedUser.Company, *actual.Attributes.Company)
	assert.Equal(t, expectedUser.Cluster+"/", *actual.Attributes.Cluster)
	assert.Equal(t, expectedUser.URL, *actual.Attributes.URL)
	assert.Equal(t, expectedUser.Bio, *actual.Attributes.Bio)
	assert.Equal(t, expectedUser.FeatureLevel, *actual.Attributes.FeatureLevel)
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

func assertUser(t *testing.T, actual *app.UserData, expectedUser accountrepo.User, expectedIdentity accountrepo.Identity) {
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
	assert.Equal(t, expectedUser.Cluster+"/", *actual.Attributes.Cluster)
}

func assertSingleUserResponseHeaders(t *testing.T, res http.ResponseWriter, appUser *app.User, modelUser accountrepo.User) {
	require.NotNil(t, res.Header()[app.LastModified])
	// assert.Equal(t, getUserUpdatedAt(*appUser).UTC().Format(http.TimeFormat), res.Header()[app.LastModified][0])
	require.NotNil(t, res.Header()[app.ETag])
	require.NotNil(t, res.Header()[app.CacheControl])
	// assert.Equal(t, app.GenerateEntityTag(modelUser), res.Header()[app.ETag][0])
}

func assertMultiUsersResponseHeaders(t *testing.T, res http.ResponseWriter, lastCreatedUser accountrepo.User) {
	require.NotNil(t, res.Header()[app.LastModified])
	// assert.Equal(t, lastCreatedUser.UpdatedAt.Truncate(time.Second).UTC().Format(http.TimeFormat), res.Header()[app.LastModified][0])
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

func WithUpdatedEmailPrivate(emailPrivate bool) UpdateUserOption {
	return func(attrs *app.UpdateIdentityDataAttributes) {
		attrs.EmailPrivate = &emailPrivate
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
		entities[i] = accountrepo.User{
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

func (d *dummyUserProfileService) CreateOrUpdate(ctx context.Context, keycloakUserProfile *login.KeycloakUserRequest, accessToken string, keycloakProfileURL string) (*string, bool, error) {
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
	identity.ProviderType = accountrepo.KeycloakIDP
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
	user.Cluster = "https://some.cluster.com"
	user.FeatureLevel = accountrepo.DefaultFeatureLevel
	rhdUserName := "somerhdusername"
	approved := false

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)

	// when
	createUserPayload := newCreateUsersPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, &rhdUserName, user.ID.String(), &user.Cluster, &identity.RegistrationCompleted, &approved, user.ContextInformation)

	// then
	_, appUser := test.CreateUsersOK(s.T(), secureService.Context, secureService, secureController, createUserPayload)
	assertCreatedUser(s.T(), appUser.Data, user, identity)
}

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountForExistingUserInDbFails() {
	user := testsupport.TestUser
	identity := testsupport.TestIdentity
	identity.User = user
	identity.ProviderType = ""
	user.Cluster = "https://some.cluster.com"

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)

	createUserPayload := newCreateUsersPayload(&user.Email, nil, nil, nil, nil, nil, &identity.Username, nil, user.ID.String(), &user.Cluster, nil, nil, nil)

	// First attempt should be OK
	test.CreateUsersOK(s.T(), secureService.Context, secureService, secureController, createUserPayload)

	// Another call with the same email and username should fail
	test.CreateUsersConflict(s.T(), secureService.Context, secureService, secureController, createUserPayload)

	newEmail := uuid.NewV4().String() + user.Email
	payloadWithSameUsername := newCreateUsersPayload(&newEmail, nil, nil, nil, nil, nil, &identity.Username, nil, user.ID.String(), &user.Cluster, nil, nil, nil)
	// Another call with the same username should fail
	test.CreateUsersConflict(s.T(), secureService.Context, secureService, secureController, payloadWithSameUsername)

	newUsername := uuid.NewV4().String() + identity.Username
	payloadWithSameEmail := newCreateUsersPayload(&user.Email, nil, nil, nil, nil, nil, &newUsername, nil, user.ID.String(), &user.Cluster, nil, nil, nil)
	// Another call with the same email should fail
	test.CreateUsersConflict(s.T(), secureService.Context, secureService, secureController, payloadWithSameEmail)
}

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountWithRequiredFieldsOnlyOK() {
	s.checkCreateUserAsServiceAccountOK(fmt.Sprintf("testuser%s@email.com", uuid.NewV4().String()))
}

func (s *UsersControllerTestSuite) checkCreateUserAsServiceAccountOK(email string) {
	user := accountrepo.User{
		ID:           uuid.NewV4(),
		Email:        email,
		Cluster:      "some cluster",
		FeatureLevel: accountrepo.DefaultFeatureLevel,
	}
	identity := accountrepo.Identity{
		ID:       uuid.NewV4(),
		Username: "TestDeveloper" + uuid.NewV4().String(),
		User:     user,
	}

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)

	createUserPayload := newCreateUsersPayload(&email, nil, nil, nil, nil, nil, &identity.Username, nil, user.ID.String(), &user.Cluster, nil, nil, nil)

	// With only required fields should be OK
	_, appUser := test.CreateUsersOK(s.T(), secureService.Context, secureService, secureController, createUserPayload)
	assertCreatedUser(s.T(), appUser.Data, user, identity)
}

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountWithMissingRequiredFieldsFails() {
	user := testsupport.TestUser
	cluster := "some cluster"

	// Missing username
	createUserPayload := newCreateUsersPayload(&user.Email, nil, nil, nil, nil, nil, nil, nil, user.ID.String(), &cluster, nil, nil, nil)
	require.NotNil(s.T(), createUserPayload.Validate())

	// Missing email
	createUserPayload = newCreateUsersPayload(nil, nil, nil, nil, nil, nil, nil, nil, user.ID.String(), &cluster, nil, nil, nil)
	require.NotNil(s.T(), createUserPayload.Validate())

	// Missing cluster
	createUserPayload = newCreateUsersPayload(&user.Email, nil, nil, nil, nil, nil, nil, nil, user.ID.String(), nil, nil, nil, nil)
	require.NotNil(s.T(), createUserPayload.Validate())

	// Missing RHD user ID
	createUserPayload = newCreateUsersPayload(&user.Email, nil, nil, nil, nil, nil, nil, nil, "", &cluster, nil, nil, nil)
	require.NotNil(s.T(), createUserPayload.Validate())
}

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountUnauthorized() {
	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity

	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestIdentity)

	// then
	createUserPayload := newCreateUsersPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, nil, user.ID.String(), &user.Cluster, &identity.RegistrationCompleted, nil, user.ContextInformation)
	test.CreateUsersUnauthorized(s.T(), secureService.Context, secureService, secureController, createUserPayload)
}

func (s *UsersControllerTestSuite) TestCreateUserAsNonServiceAccountUnauthorized() {
	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity

	secureService, secureController := s.SecuredController(testsupport.TestIdentity)

	// then
	createUserPayload := newCreateUsersPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, nil, user.ID.String(), &user.Cluster, &identity.RegistrationCompleted, nil, user.ContextInformation)
	test.CreateUsersUnauthorized(s.T(), secureService.Context, secureService, secureController, createUserPayload)
}

func (s *UsersControllerTestSuite) TestCreateUserAsServiceAccountForPreviewUserIgnored() {
	// Ignored
	s.checkCreateUserAsServiceAccountForPreviewUserIgnored(fmt.Sprintf("%s+preview%s@redhat.com", uuid.NewV4().String(), uuid.NewV4().String()))
	s.checkCreateUserAsServiceAccountForPreviewUserIgnored("someuser+preview@redhat.com")

	// Not ignored
	s.checkCreateUserAsServiceAccountOK(fmt.Sprintf("%s+preview@email.com", uuid.NewV4().String()))
	s.checkCreateUserAsServiceAccountOK(fmt.Sprintf("preview%s@redhat.com", uuid.NewV4().String()))
	s.checkCreateUserAsServiceAccountOK(fmt.Sprintf("%s@redhat.com", uuid.NewV4().String()))
}

func (s *UsersControllerTestSuite) checkCreateUserAsServiceAccountForPreviewUserIgnored(email string) {
	secureService, secureController := s.SecuredServiceAccountController(testsupport.TestOnlineRegistrationAppIdentity)

	username := "someuser"
	cluster := "some.cluster"
	createUserPayload := newCreateUsersPayload(&email, nil, nil, nil, nil, nil, &username, nil, uuid.NewV4().String(), &cluster, nil, nil, nil)

	// With only required fields should be OK
	_, appUser := test.CreateUsersOK(s.T(), secureService.Context, secureService, secureController, createUserPayload)
	require.NotNil(s.T(), appUser)
	assertCreatedUser(s.T(), appUser.Data, accountrepo.User{Cluster: cluster, Email: email}, accountrepo.Identity{Username: username})
}

func (s *UsersControllerTestSuite) TestCreateUserUnauthorized() {
	// given
	user := testsupport.TestUser
	identity := testsupport.TestIdentity

	// then
	createUserPayload := newCreateUsersPayload(&user.Email, &user.FullName, &user.Bio, &user.ImageURL, &user.URL, &user.Company, &identity.Username, nil, user.ID.String(), &user.Cluster, &identity.RegistrationCompleted, nil, user.ContextInformation)
	test.CreateUsersUnauthorized(s.T(), context.Background(), nil, s.controller, createUserPayload)
}

func newCreateUsersPayload(email, fullName, bio, imageURL, profileURL, company, username, rhdUsername *string, rhdUserID string, cluster *string, registrationCompleted, approved *bool, contextInformation map[string]interface{}) *app.CreateUsersPayload {
	providerType := "SomeRandomType" // Should be ignored

	attributes := app.CreateIdentityDataAttributes{
		//UserID:                userID,
		Approved:              approved,
		RhdUsername:           rhdUsername,
		RhdUserID:             rhdUserID,
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

type DummyEmailVerificationService struct {
	success bool
}

func (s *DummyEmailVerificationService) SendVerificationCode(ctx context.Context, req *goa.RequestData, identity accountrepo.Identity) (*accountrepo.VerificationCode, error) {
	if s.success {
		return nil, nil
	}
	return nil, errors.NewInternalErrorFromString(ctx, "failed to send out email")
}

func (s *DummyEmailVerificationService) VerifyCode(ctx context.Context, code string) (*accountrepo.VerificationCode, error) {
	return nil, nil
}

type dummyTenantService struct {
	identityID uuid.UUID
	error
}

func (s *dummyTenantService) Init(ctx context.Context) error {
	return nil
}

func (s *dummyTenantService) Delete(ctx context.Context, identityID uuid.UUID) error {
	s.identityID = identityID
	return s.error
}

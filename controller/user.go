package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/wit"

	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/pkg/errors"
)

// UserController implements the user resource.
type UserController struct {
	*goa.Controller
	db                 application.DB
	config             UserControllerConfiguration
	tokenManager       token.Manager
	InitTenant         func(ctx context.Context) error
	userProfileService login.UserProfileService
	RemoteWITService   wit.RemoteWITService
}

// UserControllerConfiguration the Configuration for the UserController
type UserControllerConfiguration interface {
	GetCacheControlUser() string
	GetKeycloakAccountEndpoint(*goa.RequestData) (string, error)
	GetWITURL(*goa.RequestData) (string, error)
}

// NewUserController creates a user controller.
func NewUserController(service *goa.Service, db application.DB, tokenManager token.Manager, userProfileService login.UserProfileService, config UserControllerConfiguration) *UserController {
	return &UserController{
		Controller:         service.NewController("UserController"),
		db:                 db,
		tokenManager:       tokenManager,
		config:             config,
		userProfileService: userProfileService,
		RemoteWITService:   &wit.RemoteWITServiceCaller{},
	}
}

// Show returns the authorized user based on the provided Token
func (c *UserController) Show(ctx *app.ShowUserContext) error {
	id, err := c.tokenManager.Locate(ctx)
	if err != nil {
		jerrors, _ := jsonapi.ErrorToJSONAPIErrors(ctx, goa.ErrBadRequest(err.Error()))
		return ctx.BadRequest(jerrors)
	}

	return application.Transactional(c.db, func(appl application.Application) error {
		identity, err := appl.Identities().Load(ctx, id)
		if err != nil || identity == nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": id,
			}, "Auth token containers id %s of unknown Identity", id)
			jerrors, _ := jsonapi.ErrorToJSONAPIErrors(ctx, goa.ErrUnauthorized(fmt.Sprintf("Auth token contains id %s of unknown Identity\n", id)))
			return ctx.Unauthorized(jerrors)
		}
		var user *account.User
		userID := identity.UserID
		if userID.Valid {
			user, err = appl.Users().Load(ctx.Context, userID.UUID)
			if err != nil {
				return jsonapi.JSONErrorResponse(ctx, errors.Wrap(err, fmt.Sprintf("Can't load user with id %s", userID.UUID)))
			}
		}
		return ctx.ConditionalRequest(*user, c.config.GetCacheControlUser, func() error {
			if c.InitTenant != nil {
				go func(ctx context.Context) {
					c.InitTenant(ctx)
				}(ctx)
			}
			return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity))
		})
	})
}

// Update handles update api
func (c *UserController) Update(ctx *app.UpdateUserContext) error {
	id, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, autherrors.NewUnauthorizedError(err.Error()))
	}

	keycloakUserProfile := &login.KeycloakUserProfile{}
	keycloakUserProfile.Attributes = &login.KeycloakUserProfileAttributes{}

	var isKeycloakUserProfileUpdateNeeded bool
	// prepare for updating keycloak user profile
	tokenString := goajwt.ContextJWT(ctx).Raw
	accountAPIEndpoint, err := c.config.GetKeycloakAccountEndpoint(ctx.RequestData)

	var identity *account.Identity
	var user *account.User

	err = application.Transactional(c.db, func(appl application.Application) error {
		identity, err = appl.Identities().Load(ctx, *id)
		if err != nil {
			return autherrors.NewUnauthorizedError(fmt.Sprintf("auth token contains id %s of unknown Identity\n", *id))
		}

		if identity.UserID.Valid {
			user, err = appl.Users().Load(ctx.Context, identity.UserID.UUID)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("Can't load user with id %s", identity.UserID.UUID))
			}
		}

		updatedEmail := ctx.Payload.Data.Attributes.Email
		if updatedEmail != nil && *updatedEmail != user.Email {
			isValid := isEmailValid(*updatedEmail)
			if !isValid {
				return autherrors.NewBadParameterError("email", *updatedEmail).Expected("valid email")
			}
			isUnique, err := isEmailUnique(appl, *updatedEmail, *user)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("error updating identitity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if !isUnique {
				// TODO: Add errors.NewConflictError(..)
				return errors.Wrap(autherrors.NewBadParameterError("email", *updatedEmail).Expected("unique email"), fmt.Sprintf("email : %s is already in use", *updatedEmail))
			}
			user.Email = *updatedEmail
			isKeycloakUserProfileUpdateNeeded = true
			keycloakUserProfile.Email = updatedEmail
		}

		updatedUserName := ctx.Payload.Data.Attributes.Username
		if updatedUserName != nil && *updatedUserName != identity.Username {
			isValid := isUsernameValid(*updatedUserName)
			if !isValid {
				return errors.Wrap(autherrors.NewBadParameterError("username", "required"), fmt.Sprintf("invalid value assigned to username for identity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if identity.RegistrationCompleted {
				return autherrors.NewForbiddenError(fmt.Sprintf("username cannot be updated more than once for identity id %s ", *id))
			}
			isUnique, err := isUsernameUnique(appl, *updatedUserName, *identity)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("error updating identitity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if !isUnique {
				// TODO : Add errors.NewConflictError(..)
				return errors.Wrap(autherrors.NewBadParameterError("username", *updatedUserName).Expected("unique username"), fmt.Sprintf("username : %s is already in use", *updatedUserName))
			}
			identity.Username = *updatedUserName
			isKeycloakUserProfileUpdateNeeded = true
			keycloakUserProfile.Username = updatedUserName
		}

		updatedRegistratedCompleted := ctx.Payload.Data.Attributes.RegistrationCompleted
		if updatedRegistratedCompleted != nil {
			if !*updatedRegistratedCompleted {
				log.Error(ctx, map[string]interface{}{
					"registration_completed": *updatedRegistratedCompleted,
					"user_id":                identity.UserID.UUID,
					"identity_id":            identity.ID,
				}, "invalid parameter assignment")

				return errors.Wrap(autherrors.NewBadParameterError("registration_completed", *updatedRegistratedCompleted).Expected("should be true or nil"), fmt.Sprintf("invalid value assigned to registration_completed for identity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			identity.RegistrationCompleted = true
		}

		updatedBio := ctx.Payload.Data.Attributes.Bio
		if updatedBio != nil && *updatedBio != user.Bio {
			user.Bio = *updatedBio
			isKeycloakUserProfileUpdateNeeded = true
			(*keycloakUserProfile.Attributes)[login.BioAttributeName] = []string{*updatedBio}
		}
		updatedFullName := ctx.Payload.Data.Attributes.FullName
		if updatedFullName != nil && *updatedFullName != user.FullName {
			*updatedFullName = standardizeSpaces(*updatedFullName)
			user.FullName = *updatedFullName
			// In KC, we store as first name and last name.
			nameComponents := strings.Split(*updatedFullName, " ")
			firstName := nameComponents[0]
			lastName := ""
			if len(nameComponents) > 1 {
				lastName = strings.Join(nameComponents[1:], " ")
			}
			isKeycloakUserProfileUpdateNeeded = true
			keycloakUserProfile.FirstName = &firstName
			keycloakUserProfile.LastName = &lastName
		}
		updatedImageURL := ctx.Payload.Data.Attributes.ImageURL
		if updatedImageURL != nil && *updatedImageURL != user.ImageURL {
			user.ImageURL = *updatedImageURL
			isKeycloakUserProfileUpdateNeeded = true
			(*keycloakUserProfile.Attributes)[login.ImageURLAttributeName] = []string{*updatedImageURL}

		}
		updateURL := ctx.Payload.Data.Attributes.URL
		if updateURL != nil && *updateURL != user.URL {
			user.URL = *updateURL
			isKeycloakUserProfileUpdateNeeded = true

			(*keycloakUserProfile.Attributes)[login.URLAttributeName] = []string{*updateURL}
		}

		updatedCompany := ctx.Payload.Data.Attributes.Company
		if updatedCompany != nil && *updatedCompany != user.Company {
			user.Company = *updatedCompany
			isKeycloakUserProfileUpdateNeeded = true
			(*keycloakUserProfile.Attributes)[login.CompanyAttributeName] = []string{*updatedCompany}
		}

		// If none of the 'extra' attributes were present, we better make that section nil
		// so that the Attributes section is omitted in the payload sent to KC

		if updatedBio == nil && updatedImageURL == nil && updateURL == nil && keycloakUserProfile != nil {
			keycloakUserProfile.Attributes = nil
		}

		updatedContextInformation := ctx.Payload.Data.Attributes.ContextInformation
		if updatedContextInformation != nil {
			// if user.ContextInformation , we get to PATCH the ContextInformation field,
			// instead of over-writing it altogether. Note: The PATCH-ing is only for the
			// 1st level of JSON.
			if user.ContextInformation == nil {
				user.ContextInformation = make(map[string]interface{})
			}
			for fieldName, fieldValue := range updatedContextInformation {
				// Save it as is, for short-term.
				user.ContextInformation[fieldName] = fieldValue
			}
		}

		err = appl.Users().Save(ctx, user)
		if err != nil {
			return err
		}

		err = appl.Identities().Save(ctx, identity)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": id.String(),
			"err":         err,
		}, "failed to update user/identity")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if isKeycloakUserProfileUpdateNeeded {
		keycloakUserProfile, err = c.copyExistingKeycloakUserProfileInfo(ctx, keycloakUserProfile, tokenString, accountAPIEndpoint)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}

		err = c.userProfileService.Update(ctx, keycloakUserProfile, tokenString, accountAPIEndpoint)

		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"user_name": keycloakUserProfile.Username,
				"email":     keycloakUserProfile.Email,
				"err":       err,
			}, "failed to update keycloak account")

			jerrors, _ := jsonapi.ErrorToJSONAPIErrors(ctx, err)

			// We have mapped keycloak's 500 InternalServerError to our errors.BadParameterError
			// because this scenario is directly associated with attempts to update
			// duplicate email and/or username.
			switch err.(type) {
			default:
				return ctx.BadRequest(jerrors)
			// case errors.BadParameterError:
			// 	return ctx.Conflict(jerrors)
			case autherrors.UnauthorizedError:
				return ctx.Unauthorized(jerrors)
			}
		}
	}
	err = c.updateWITUser(ctx, ctx.RequestData, identity.ID.String())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"user_id":     user.ID,
			"identity_id": identity.ID,
			"username":    identity.Username,
			"err":         err,
		}, "failed to update WIT user/identity")
		// Let's not disrupt the response if there was an issue with updating WIT.
	}

	return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity))
}

func (c *UserController) copyExistingKeycloakUserProfileInfo(ctx context.Context, keycloakUserProfile *login.KeycloakUserProfile, tokenString string, accountAPIEndpoint string) (*login.KeycloakUserProfile, error) {

	// The keycloak API doesn't support PATCH, hence the entire info needs
	// to be sent over for User profile updation in Keycloak. So the POST request to KC needs
	// to have everything - whatever we are updating, and whatever are not.

	if keycloakUserProfile == nil {
		keycloakUserProfile = &login.KeycloakUserProfile{}
		keycloakUserProfile.Attributes = &login.KeycloakUserProfileAttributes{}
	}

	existingProfile, err := c.getKeycloakProfileInformation(ctx, tokenString, accountAPIEndpoint)
	if err != nil {
		return nil, err
	}

	keycloakUserProfile = mergeKeycloakUserProfileInfo(keycloakUserProfile, existingProfile)

	return keycloakUserProfile, nil
}

func (c *UserController) getKeycloakProfileInformation(ctx context.Context, tokenString string, accountAPIEndpoint string) (*login.KeycloakUserProfileResponse, error) {

	response, err := c.userProfileService.Get(ctx, tokenString, accountAPIEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to fetch keycloak account information")
	}
	return response, err
}

func (c *UserController) updateWITUser(ctx *app.UpdateUserContext, request *goa.RequestData, identityID string) error {
	updateUserPayload := &app.UpdateUsersPayload{
		Data: &app.UpdateUserData{
			Attributes: &app.UpdateIdentityDataAttributes{
				Bio:                   ctx.Payload.Data.Attributes.Bio,
				Company:               ctx.Payload.Data.Attributes.Company,
				ContextInformation:    ctx.Payload.Data.Attributes.ContextInformation,
				Email:                 ctx.Payload.Data.Attributes.Email,
				FullName:              ctx.Payload.Data.Attributes.FullName,
				ImageURL:              ctx.Payload.Data.Attributes.ImageURL,
				RegistrationCompleted: ctx.Payload.Data.Attributes.RegistrationCompleted,
				URL:      ctx.Payload.Data.Attributes.URL,
				Username: ctx.Payload.Data.Attributes.Username,
			},
			Type: ctx.Payload.Data.Type,
		},
	}
	witURL, err := c.config.GetWITURL(ctx.RequestData)
	if err != nil {
		return err
	}
	return c.RemoteWITService.UpdateWITUser(ctx, request, updateUserPayload, witURL, identityID)
}

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/remoteservice"
	"github.com/fabric8-services/fabric8-auth/rest"

	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

// UsersController implements the users resource.
type UsersController struct {
	*goa.Controller
	db                 application.DB
	config             UsersControllerConfiguration
	userProfileService login.UserProfileService
	RemoteWITService   remoteservice.RemoteWITService
}

// UsersControllerConfiguration the Configuration for the UsersController
type UsersControllerConfiguration interface {
	GetCacheControlUsers() string
	GetCacheControlUser() string
	GetKeycloakAccountEndpoint(*goa.RequestData) (string, error)
	GetWITEndpoint(*goa.RequestData) (string, error)
}

// NewUsersController creates a users controller.
func NewUsersController(service *goa.Service, db application.DB, config UsersControllerConfiguration, userProfileService login.UserProfileService) *UsersController {
	return &UsersController{
		Controller:         service.NewController("UsersController"),
		db:                 db,
		config:             config,
		userProfileService: userProfileService,
		RemoteWITService:   &remoteservice.RemoteWITServiceCaller{},
	}
}

// Show runs the show action.
func (c *UsersController) Show(ctx *app.ShowUsersContext) error {
	return application.Transactional(c.db, func(appl application.Application) error {
		identityID, err := uuid.FromString(ctx.ID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, errs.Wrap(errors.NewBadParameterError("identity_id", ctx.ID), err.Error()))
		}
		identity, err := appl.Identities().Load(ctx.Context, identityID)
		if err != nil {
			jerrors, httpStatusCode := jsonapi.ErrorToJSONAPIErrors(ctx, err)
			return ctx.ResponseData.Service.Send(ctx.Context, httpStatusCode, jerrors)
		}
		var user *account.User
		userID := identity.UserID
		if userID.Valid {
			user, err = appl.Users().Load(ctx.Context, userID.UUID)
			if err != nil {
				return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError(fmt.Sprintf("User ID %s not valid", userID.UUID), err))
			}
		}
		return ctx.ConditionalRequest(*user, c.config.GetCacheControlUser, func() error {
			return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity))
		})
	})
}

func mergeKeycloakUserProfileInfo(keycloakUserProfile *login.KeycloakUserProfile, existingProfile *login.KeycloakUserProfileResponse) *login.KeycloakUserProfile {

	// If the *new* FirstName has already been set, we won't be updating it with the *existing* value
	if existingProfile.FirstName != nil && keycloakUserProfile.FirstName == nil {
		keycloakUserProfile.FirstName = existingProfile.FirstName
	}
	if existingProfile.LastName != nil && keycloakUserProfile.LastName == nil {
		keycloakUserProfile.LastName = existingProfile.LastName
	}
	if existingProfile.Email != nil && keycloakUserProfile.Email == nil {
		keycloakUserProfile.Email = existingProfile.Email
	}

	if existingProfile.Attributes != nil && keycloakUserProfile.Attributes != nil {

		// If there are existing attributes, we overwite only those
		// handled by the Users service in platform. The value would be non-nil if they
		// they are to be updated by the PATCH request.

		if (*keycloakUserProfile.Attributes)[login.ImageURLAttributeName] != nil {
			(*existingProfile.Attributes)[login.ImageURLAttributeName] = (*keycloakUserProfile.Attributes)[login.ImageURLAttributeName]
		}
		if (*keycloakUserProfile.Attributes)[login.BioAttributeName] != nil {
			(*existingProfile.Attributes)[login.BioAttributeName] = (*keycloakUserProfile.Attributes)[login.BioAttributeName]
		}
		if (*keycloakUserProfile.Attributes)[login.URLAttributeName] != nil {
			(*existingProfile.Attributes)[login.URLAttributeName] = (*keycloakUserProfile.Attributes)[login.URLAttributeName]
		}
		if (*keycloakUserProfile.Attributes)[login.CompanyAttributeName] != nil {
			(*existingProfile.Attributes)[login.CompanyAttributeName] = (*keycloakUserProfile.Attributes)[login.CompanyAttributeName]
		}
		if (*keycloakUserProfile.Attributes)[login.ApprovedAttributeName] != nil {
			(*existingProfile.Attributes)[login.ApprovedAttributeName] = (*keycloakUserProfile.Attributes)[login.ApprovedAttributeName]
		}

		// Copy over the rest of the attributes as well.
		keycloakUserProfile.Attributes = existingProfile.Attributes
	}

	if existingProfile.Username != nil && keycloakUserProfile.Username == nil {
		keycloakUserProfile.Username = existingProfile.Username
	}

	return keycloakUserProfile
}

func (c *UsersController) copyExistingKeycloakUserProfileInfo(ctx context.Context, keycloakUserProfile *login.KeycloakUserProfile, tokenString string, accountAPIEndpoint string) (*login.KeycloakUserProfile, error) {

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

func (c *UsersController) getKeycloakProfileInformation(ctx context.Context, tokenString string, accountAPIEndpoint string) (*login.KeycloakUserProfileResponse, error) {

	response, err := c.userProfileService.Get(ctx, tokenString, accountAPIEndpoint)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "failed to fetch keycloak account information")
	}
	return response, err
}

// Update updates the authorized user based on the provided Token
func (c *UsersController) Update(ctx *app.UpdateUsersContext) error {

	id, err := login.ContextIdentity(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(err.Error()))
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
			return errors.NewUnauthorizedError(fmt.Sprintf("auth token contains id %s of unknown Identity\n", *id))
		}

		if identity.UserID.Valid {
			user, err = appl.Users().Load(ctx.Context, identity.UserID.UUID)
			if err != nil {
				return errs.Wrap(err, fmt.Sprintf("Can't load user with id %s", identity.UserID.UUID))
			}
		}

		updatedEmail := ctx.Payload.Data.Attributes.Email
		if updatedEmail != nil && *updatedEmail != user.Email {
			isValid := isEmailValid(*updatedEmail)
			if !isValid {
				return errors.NewBadParameterError("email", *updatedEmail).Expected("valid email")
			}
			isUnique, err := isEmailUnique(appl, *updatedEmail, *user)
			if err != nil {
				return errs.Wrap(err, fmt.Sprintf("error updating identitity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if !isUnique {
				// TODO: Add errors.NewConflictError(..)
				return errs.Wrap(errors.NewBadParameterError("email", *updatedEmail).Expected("unique email"), fmt.Sprintf("email : %s is already in use", *updatedEmail))
			}
			user.Email = *updatedEmail
			isKeycloakUserProfileUpdateNeeded = true
			keycloakUserProfile.Email = updatedEmail
		}

		updatedUserName := ctx.Payload.Data.Attributes.Username
		if updatedUserName != nil && *updatedUserName != identity.Username {
			isValid := isUsernameValid(*updatedUserName)
			if !isValid {
				return errs.Wrap(errors.NewBadParameterError("username", "required"), fmt.Sprintf("invalid value assigned to username for identity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if identity.RegistrationCompleted {
				return errors.NewForbiddenError(fmt.Sprintf("username cannot be updated more than once for identity id %s ", *id))
			}
			isUnique, err := isUsernameUnique(appl, *updatedUserName, *identity)
			if err != nil {
				return errs.Wrap(err, fmt.Sprintf("error updating identitity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if !isUnique {
				// TODO : Add errors.NewConflictError(..)
				return errs.Wrap(errors.NewBadParameterError("username", *updatedUserName).Expected("unique username"), fmt.Sprintf("username : %s is already in use", *updatedUserName))
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

				return errs.Wrap(errors.NewBadParameterError("registration_completed", *updatedRegistratedCompleted).Expected("should be true or nil"), fmt.Sprintf("invalid value assigned to registration_completed for identity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
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
			"user_name": identity.ID,
			"err":       err,
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
			case errors.BadParameterError:
				return ctx.Conflict(jerrors)
			case errors.UnauthorizedError:
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

func (c *UsersController) updateWITUser(ctx *app.UpdateUsersContext, request *goa.RequestData, identityID string) error {
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
	WITEndpoint, err := c.config.GetWITEndpoint(ctx.RequestData)
	if err != nil {
		return err
	}
	return c.RemoteWITService.UpdateWITUser(ctx, request, updateUserPayload, WITEndpoint, identityID)
}

func isEmailValid(email string) bool {
	// TODO: Add regex to verify email format, later
	if len(strings.TrimSpace(email)) > 0 {
		return true
	}
	return false
}

func isUsernameValid(username string) bool {
	if len(strings.TrimSpace(username)) > 0 {
		return true
	}
	return false
}

func isUsernameUnique(appl application.Application, username string, identity account.Identity) (bool, error) {
	usersWithSameUserName, err := appl.Identities().Query(account.IdentityFilterByUsername(username), account.IdentityFilterByProviderType(account.KeycloakIDP))
	if err != nil {
		log.Error(nil, map[string]interface{}{
			"user_name": username,
			"err":       err,
		}, "error fetching users with username filter")
		return false, err
	}
	for _, u := range usersWithSameUserName {
		if u.UserID.UUID != identity.UserID.UUID {
			return false, nil
		}
	}
	return true, nil
}

func isEmailUnique(appl application.Application, email string, user account.User) (bool, error) {
	usersWithSameEmail, err := appl.Users().Query(account.UserFilterByEmail(email))
	if err != nil {
		log.Error(nil, map[string]interface{}{
			"email": email,
			"err":   err,
		}, "error fetching identities with email filter")
		return false, err
	}
	for _, u := range usersWithSameEmail {
		if u.ID != user.ID {
			return false, nil
		}
	}
	return true, nil
}

// List runs the list action.
func (c *UsersController) List(ctx *app.ListUsersContext) error {
	return application.Transactional(c.db, func(appl application.Application) error {
		users, identities, err := filterUsers(appl, ctx)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		return ctx.ConditionalEntities(users, c.config.GetCacheControlUsers, func() error {
			appUsers := make([]*app.UserData, len(users))
			for i := range users {
				appUser := ConvertToAppUser(ctx.RequestData, &users[i], &identities[i])
				appUsers[i] = appUser.Data
			}
			return ctx.OK(&app.UserArray{Data: appUsers})
		})
	})
}

func filterUsers(appl application.Application, ctx *app.ListUsersContext) ([]account.User, []account.Identity, error) {
	var err error
	var resultUsers []account.User
	var resultIdentities []account.Identity
	/*
		There are 2 database tables we fetch the data from : identities , users
		First, we filter on the attributes of identities table - providerType , username
		After that we use the above result to cumulatively filter on users  - email , company
	*/
	identityFilters := []func(*gorm.DB) *gorm.DB{}
	userFilters := []func(*gorm.DB) *gorm.DB{}
	/*** Start filtering on Identities table ****/
	if ctx.FilterUsername != nil {
		identityFilters = append(identityFilters, account.IdentityFilterByUsername(*ctx.FilterUsername))
	}
	if ctx.FilterRegistrationCompleted != nil {
		identityFilters = append(identityFilters, account.IdentityFilterByRegistrationCompleted(*ctx.FilterRegistrationCompleted))
	}
	// Add more filters when needed , here. ..
	if len(identityFilters) != 0 {
		identityFilters = append(identityFilters, account.IdentityFilterByProviderType(account.KeycloakIDP))
		identityFilters = append(identityFilters, account.IdentityWithUser())
		// From a data model perspective, we are querying by identity ( and not user )
		filteredIdentities, err := appl.Identities().Query(identityFilters...)
		if err != nil {
			return nil, nil, errs.Wrap(err, "error fetching identities with filter(s)")
		}
		// cumulatively filter out those not matching the user-based filters.
		for _, identity := range filteredIdentities {
			// this is where you keep trying all other filters one by one for 'user' fields like email.
			if ctx.FilterEmail == nil || identity.User.Email == *ctx.FilterEmail {
				resultUsers = append(resultUsers, identity.User)
				resultIdentities = append(resultIdentities, identity)
			}
		}
	} else {
		var filteredUsers []account.User
		/*** Start filtering on Users table ****/
		if ctx.FilterEmail != nil {
			userFilters = append(userFilters, account.UserFilterByEmail(*ctx.FilterEmail))
		}
		// .. Add other filters in future when needed into the userFilters slice in the above manner.
		if len(userFilters) != 0 {
			filteredUsers, err = appl.Users().Query(userFilters...)
		} else {
			// Soft-kill the API for listing all Users /api/users
			resultUsers = []account.User{}
			resultIdentities = []account.Identity{}
			return resultUsers, resultIdentities, nil
		}
		if err != nil {
			return nil, nil, errs.Wrap(err, "error fetching users")
		}
		resultUsers, resultIdentities, err = LoadKeyCloakIdentities(appl, filteredUsers)
		if err != nil {
			return nil, nil, errs.Wrap(err, "error fetching keycloak identities")
		}
	}
	return resultUsers, resultIdentities, nil
}

// LoadKeyCloakIdentities loads keycloak identities for the users and returns the valid users along with their KC identities
// (if a user is missing his/her KC identity, he/she is filtered out of the result array)
func LoadKeyCloakIdentities(appl application.Application, users []account.User) ([]account.User, []account.Identity, error) {
	var resultUsers []account.User
	var resultIdentities []account.Identity
	for _, user := range users {
		identity, err := loadKeyCloakIdentity(appl, user)
		// if we can't find the Keycloak identity
		if err != nil {
			log.Error(nil, map[string]interface{}{"user": user, "err": err}, "unable to load user keycloak identity")
		} else {
			resultUsers = append(resultUsers, user)
			resultIdentities = append(resultIdentities, *identity)
		}
	}
	return resultUsers, resultIdentities, nil
}

func loadKeyCloakIdentity(appl application.Application, user account.User) (*account.Identity, error) {
	identities, err := appl.Identities().Query(account.IdentityFilterByUserID(user.ID))
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		if identity.ProviderType == account.KeycloakIDP {
			return &identity, nil
		}
	}
	return nil, fmt.Errorf("Can't find Keycloak Identity for user %s", user.Email)
}

// ConvertToAppUser converts a complete Identity object into REST representation
func ConvertToAppUser(request *goa.RequestData, user *account.User, identity *account.Identity) *app.User {
	userID := user.ID.String()
	identityID := identity.ID.String()
	fullName := user.FullName
	userName := identity.Username
	registrationCompleted := identity.RegistrationCompleted
	providerType := identity.ProviderType
	var imageURL string
	var bio string
	var userURL string
	var email string
	var createdAt time.Time
	var updatedAt time.Time
	var company string
	var contextInformation map[string]interface{}

	if user != nil {
		fullName = user.FullName
		imageURL = user.ImageURL
		bio = user.Bio
		userURL = user.URL
		email = user.Email
		company = user.Company
		contextInformation = user.ContextInformation
		// CreatedAt and UpdatedAt fields in the resulting app.Identity are based on the 'user' entity
		createdAt = user.CreatedAt
		updatedAt = user.UpdatedAt
	}

	converted := app.User{
		Data: &app.UserData{
			ID:   &identityID,
			Type: "identities",
			Attributes: &app.UserDataAttributes{
				CreatedAt:             &createdAt,
				UpdatedAt:             &updatedAt,
				Username:              &userName,
				FullName:              &fullName,
				ImageURL:              &imageURL,
				Bio:                   &bio,
				URL:                   &userURL,
				UserID:                &userID,
				IdentityID:            &identityID,
				ProviderType:          &providerType,
				Email:                 &email,
				Company:               &company,
				ContextInformation:    make(map[string]interface{}),
				RegistrationCompleted: &registrationCompleted,
			},
			Links: createUserLinks(request, &identity.ID),
		},
	}
	for name, value := range contextInformation {
		if value == nil {
			// this can be used to unset a key in contextInformation
			continue
		}
		converted.Data.Attributes.ContextInformation[name] = value
	}
	return &converted
}

// ConvertUsersSimple converts a array of simple Identity IDs into a Generic Reletionship List
func ConvertUsersSimple(request *goa.RequestData, identityIDs []interface{}) []*app.GenericData {
	ops := []*app.GenericData{}
	for _, identityID := range identityIDs {
		ops = append(ops, ConvertUserSimple(request, identityID))
	}
	return ops
}

// ConvertUserSimple converts a simple Identity ID into a Generic Reletionship
func ConvertUserSimple(request *goa.RequestData, identityID interface{}) *app.GenericData {
	t := "users"
	i := fmt.Sprint(identityID)
	return &app.GenericData{
		Type:  &t,
		ID:    &i,
		Links: createUserLinks(request, identityID),
	}
}

func createUserLinks(request *goa.RequestData, identityID interface{}) *app.GenericLinks {
	relatedURL := rest.AbsoluteURL(request, app.UsersHref(identityID))
	return &app.GenericLinks{
		Self:    &relatedURL,
		Related: &relatedURL,
	}
}

func standardizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

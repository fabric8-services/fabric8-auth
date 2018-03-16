package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/account/email"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/login/link"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/wit"

	"regexp"

	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

// UsersController implements the users resource.
type UsersController struct {
	*goa.Controller
	db                       application.DB
	config                   UsersControllerConfiguration
	userProfileService       login.UserProfileService
	RemoteWITService         wit.RemoteWITService
	EmailVerificationService email.EmailVerificationService
	keycloakLinkService      link.KeycloakIDPService
}

// UsersControllerConfiguration the Configuration for the UsersController
type UsersControllerConfiguration interface {
	GetCacheControlUsers() string
	GetCacheControlUser() string
	GetKeycloakAccountEndpoint(*goa.RequestData) (string, error)
	GetWITURL(*goa.RequestData) (string, error)
	GetKeycloakEndpointToken(*goa.RequestData) (string, error)
	GetKeycloakEndpointUsers(*goa.RequestData) (string, error)
	GetKeycloakClientID() string
	GetKeycloakSecret() string
	GetKeycloakEndpointLinkIDP(req *goa.RequestData, id string, idp string) (string, error)
	GetEmailVerifiedRedirectURL() string
	GetInternalUsersEmailAddressSuffix() string
	GetIgnoreEmailInProd() string
}

// NewUsersController creates a users controller.
func NewUsersController(service *goa.Service, db application.DB, config UsersControllerConfiguration, userProfileService login.UserProfileService, linkService link.KeycloakIDPService) *UsersController {
	return &UsersController{
		Controller:          service.NewController("UsersController"),
		db:                  db,
		config:              config,
		userProfileService:  userProfileService,
		RemoteWITService:    &wit.RemoteWITServiceCaller{},
		keycloakLinkService: linkService,
	}
}

// Show runs the show action.
func (c *UsersController) Show(ctx *app.ShowUsersContext) error {
	tenantSA := token.IsSpecificServiceAccount(ctx, token.Tenant)
	isServiceAccount := tenantSA || token.IsSpecificServiceAccount(ctx, token.Notification)

	return application.Transactional(c.db, func(appl application.Application) error {
		identityID, err := uuid.FromString(ctx.ID)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, errs.Wrap(errors.NewBadParameterError("identity_id", ctx.ID), err.Error()))
		}
		identity, err := appl.Identities().LoadWithUser(ctx.Context, identityID)
		if err != nil {
			jerrors, httpStatusCode := jsonapi.ErrorToJSONAPIErrors(ctx, err)
			return ctx.ResponseData.Service.Send(ctx.Context, httpStatusCode, jerrors)
		}

		if tenantSA && identity.User.Deprovisioned {
			// Don't return deprovisioned users for calls made by Tenant SA
			// TODO we should disable notifications for such users too but if we just return 401 for notification service request we may break it
			ctx.ResponseData.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
			ctx.ResponseData.Header().Set("WWW-Authenticate", "DEPROVISIONED description=\"Account has been deprovisioned\"")
			return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("Account has benn deprovisioned"))
		}

		return ctx.ConditionalRequest(identity.User, c.config.GetCacheControlUser, func() error {
			return ctx.OK(ConvertToAppUser(ctx.RequestData, &identity.User, identity, isServiceAccount))
		})
	})
}

// Create creates a user when requested using a service account token
func (c *UsersController) Create(ctx *app.CreateUsersContext) error {

	isSvcAccount := token.IsSpecificServiceAccount(ctx, token.OnlineRegistration)
	if !isSvcAccount {
		log.Error(ctx, nil, "The account is not an authorized service account allowed to create a new user")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("account not authorized to create users."))
	}

	// ----- Ignore users created for Preview environment
	// TODO remove this when we start using our regular user registration flow in staging environment
	preview, err := c.checkPreviewUser(ctx.Payload.Data.Attributes.Email)
	if err != nil {
		log.Error(ctx, map[string]interface{}{"err": err, "email": ctx.Payload.Data.Attributes.Email}, "unable to parse user's email")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	if preview {
		log.Info(ctx, map[string]interface{}{"email": ctx.Payload.Data.Attributes.Email}, "ignoring preview user")
		user := &account.User{Email: ctx.Payload.Data.Attributes.Email, Cluster: ctx.Payload.Data.Attributes.Cluster}
		identity := &account.Identity{Username: ctx.Payload.Data.Attributes.Username, ProviderType: account.KeycloakIDP}
		return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity, true))
	}
	// -----

	userExists, err := c.userExistsInDB(ctx, ctx.Payload.Data.Attributes.Email, ctx.Payload.Data.Attributes.Username)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	if userExists {
		return jsonapi.JSONErrorResponse(ctx, errors.NewVersionConflictError("user with such email or username already exists"))
	}

	tokenEndpoint, err := c.config.GetKeycloakEndpointToken(ctx.RequestData)
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}
	log.Info(ctx, map[string]interface{}{
		"keycloak_client_id": c.config.GetKeycloakClientID(),
		"token_endpoint":     tokenEndpoint,
	}, "will generate PAT ")
	protectedAccessToken, err := auth.GetProtectedAPIToken(ctx, tokenEndpoint, c.config.GetKeycloakClientID(), c.config.GetKeycloakSecret())
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	keycloakUserID, err := c.createOrUpdateUserInKeycloak(ctx, protectedAccessToken)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"username": ctx.Payload.Data.Attributes.Username,
		}, "failed to create user in keycloak")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	log.Info(ctx, map[string]interface{}{
		"keycloak_user_id": *keycloakUserID,
	}, "successfully created new user in keycloak")

	identityID, err := uuid.FromString(*keycloakUserID)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	identity, user, err := c.createUserInDB(ctx, identityID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":              err,
			"keycloak_user_id": *keycloakUserID,
		}, "failed to create user in DB")

		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	// finally, if all works, we create a user in WIT too.
	witURL, err := c.config.GetWITURL(ctx.RequestData)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":              err,
			"keycloak_user_id": *keycloakUserID,
		}, "failed to create user in WIT")

		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	err = c.RemoteWITService.CreateWITUser(ctx.Context, ctx.RequestData, identity, witURL, identityID.String())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":              err,
			"keycloak_user_id": *keycloakUserID,
		}, "failed to create user in WIT")
		// Not a blocker. Log the error and proceed.
	}

	return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity, true))
}

func (c *UsersController) checkPreviewUser(email string) (bool, error) {
	// Any <username>+preview*@redhat.com email matches
	return regexp.MatchString(c.config.GetIgnoreEmailInProd(), strings.ToLower(email))
}

func (c *UsersController) linkUserToRHD(ctx *app.CreateUsersContext, identityID string, rhdUsername string, rhdUserID string, protectedAccessToken string) error {
	idpName := "rhd"
	linkRequest := link.KeycloakLinkIDPRequest{
		UserID:           &rhdUserID,
		Username:         &rhdUsername,
		IdentityProvider: &idpName,
	}

	linkURL, err := c.config.GetKeycloakEndpointLinkIDP(ctx.RequestData, identityID, idpName)
	if err != nil {
		return err
	}
	return c.keycloakLinkService.Create(ctx, &linkRequest, protectedAccessToken, linkURL)
}

func rhdUserName(userAttributes app.CreateIdentityDataAttributes) string {
	rhdUsername := userAttributes.Username // Use username as RHD username by default
	if userAttributes.RhdUsername != nil {
		rhdUsername = *userAttributes.RhdUsername
	}
	return rhdUsername
}

// createOrUpdateUserInKeycloak creates a new user in Keycloak. If the user already exists then try to update the user
func (c *UsersController) createOrUpdateUserInKeycloak(ctx *app.CreateUsersContext, protectedAccessToken string) (*string, error) {

	// All the below attributes are mandatory: "username", "email"
	// "cluster" is mandatory too but we do not store it in Keycloak

	userAttributes := ctx.Payload.Data.Attributes

	keycloakUser := login.KeytcloakUserRequest{
		Username: &userAttributes.Username,
		Email:    &userAttributes.Email,
	}

	attributes := login.KeycloakUserProfileAttributes{}

	approved := true // Approved by default
	if userAttributes.Approved != nil {
		approved = *userAttributes.Approved
	}
	attributes[login.ApprovedAttributeName] = []string{fmt.Sprint(approved)}

	company := "" // Empty string by default
	if userAttributes.Company != nil {
		company = *userAttributes.Company
	}
	attributes[login.CompanyAttributeName] = []string{company}

	rhdUsername := rhdUserName(*userAttributes)
	attributes[login.RHDUsernameAttribute] = []string{rhdUsername}

	keycloakUser.Attributes = &attributes

	if userAttributes.FullName != nil {
		nameComponents := strings.Split(*userAttributes.FullName, " ")
		firstName := nameComponents[0]
		lastName := ""
		if len(nameComponents) > 1 {
			lastName = strings.Join(nameComponents[1:], " ")
		}

		keycloakUser.FirstName = &firstName
		keycloakUser.LastName = &lastName
	}

	usersEndpoint, err := c.config.GetKeycloakEndpointUsers(ctx.RequestData)
	if err != nil {
		return nil, err
	}

	userURL, created, err := c.userProfileService.CreateOrUpdate(ctx, &keycloakUser, protectedAccessToken, usersEndpoint)
	if err != nil {
		return nil, err
	}

	// TODO: Handle error, check if there was actually a URL returned.
	userURLComponents := strings.Split(*userURL, "/")
	identityID := userURLComponents[len(userURLComponents)-1]

	// Link only new accounts. Do not link already existing (and updated) ones
	if created {
		rhdUserID := userAttributes.RhdUserID
		err = c.linkUserToRHD(ctx, identityID, rhdUserName(*ctx.Payload.Data.Attributes), rhdUserID, protectedAccessToken)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":              err,
				"keycloak_user_id": identityID,
			}, "failed to link user to rhd")
			return nil, err
		}
	}

	return &identityID, nil
}

func (c *UsersController) createUserInDB(ctx *app.CreateUsersContext, identityID uuid.UUID) (*account.Identity, *account.User, error) {
	log.Debug(ctx, map[string]interface{}{"identity_id": identityID, "user attributes": ctx.Payload.Data.Attributes}, "creating a new user in DB...")
	userID := uuid.NewV4()
	var err error

	var user *account.User
	var identity *account.Identity

	// Mandatory attributes
	// "username", "email", "cluster"

	user = &account.User{
		ID:            userID,
		Email:         ctx.Payload.Data.Attributes.Email,
		Cluster:       ctx.Payload.Data.Attributes.Cluster,
		EmailPrivate:  false,
		EmailVerified: true,
		FeatureLevel:  account.DefaultFeatureLevel,
	}
	identity = &account.Identity{
		ID:           identityID,
		Username:     ctx.Payload.Data.Attributes.Username,
		ProviderType: account.KeycloakIDP, // Ignore Provider Type passed in the payload. We should always use "kc".
	}

	// associate foreign key
	identity.UserID = account.NullUUID{UUID: user.ID, Valid: true}

	// Optional Attributes
	registrationCompleted := ctx.Payload.Data.Attributes.RegistrationCompleted
	if registrationCompleted != nil {
		identity.RegistrationCompleted = true
	}

	company := ctx.Payload.Data.Attributes.Company
	if company != nil {
		user.Company = *company
	}

	fullName := ctx.Payload.Data.Attributes.FullName
	if fullName != nil {
		user.FullName = *fullName
	}

	bio := ctx.Payload.Data.Attributes.Bio
	if bio != nil {
		user.Bio = *bio
	}

	imageURL := ctx.Payload.Data.Attributes.ImageURL
	if imageURL != nil {
		user.ImageURL = *imageURL
	}

	url := ctx.Payload.Data.Attributes.URL
	if url != nil {
		user.URL = *url
	}

	featureLevel := ctx.Payload.Data.Attributes.FeatureLevel
	if featureLevel != nil {
		user.FeatureLevel = *featureLevel
	}

	contextInformation := ctx.Payload.Data.Attributes.ContextInformation
	if contextInformation != nil {
		if user.ContextInformation == nil {
			user.ContextInformation = account.ContextInformation{}
		}
		for fieldName, fieldValue := range contextInformation {
			user.ContextInformation[fieldName] = fieldValue
		}
	}

	returnErrorResponse := application.Transactional(c.db, func(appl application.Application) error {
		err = appl.Users().Create(ctx, user)
		if err != nil {
			return err
		}
		err = appl.Identities().Create(ctx, identity)
		if err != nil {
			return err
		}
		return nil
	})

	if returnErrorResponse != nil {
		return nil, nil, returnErrorResponse
	}

	identity.User = *user // being explicit

	return identity, user, nil
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
	var isEmailVerificationNeeded bool
	// prepare for updating keycloak user profile
	tokenString := jwt.ContextJWT(ctx).Raw
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
			isUnique, err := isEmailUnique(ctx, appl, *updatedEmail, *user)
			if err != nil {
				return errs.Wrap(err, fmt.Sprintf("error updating identitity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if !isUnique {
				// TODO: Add errors.NewConflictError(..)
				return errs.Wrap(errors.NewBadParameterError("email", *updatedEmail).Expected("unique email"), fmt.Sprintf("email : %s is already in use", *updatedEmail))
			}
			user.Email = *updatedEmail
			isKeycloakUserProfileUpdateNeeded = true

			isEmailVerificationNeeded = true
			user.EmailVerified = false

			keycloakUserProfile.Email = updatedEmail
		}
		// ensure that the default value is not picked up by setting it explicitly.
		keycloakUserProfile.EmailVerified = &user.EmailVerified

		updatedUserName := ctx.Payload.Data.Attributes.Username
		if updatedUserName != nil && *updatedUserName != identity.Username {
			isValid := isUsernameValid(*updatedUserName)
			if !isValid {
				return errs.Wrap(errors.NewBadParameterError("username", "required"), fmt.Sprintf("invalid value assigned to username for identity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if identity.RegistrationCompleted {
				return errors.NewForbiddenError(fmt.Sprintf("username cannot be updated more than once for identity id %s ", *id))
			}
			isUnique, err := isUsernameUnique(ctx, appl, *updatedUserName, *identity)
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

		updatedEmailPrivate := ctx.Payload.Data.Attributes.EmailPrivate
		if updatedEmailPrivate != nil {
			user.EmailPrivate = *updatedEmailPrivate
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

		err := c.updateFeatureLevel(ctx, user, ctx.Payload.Data.Attributes.FeatureLevel)
		if err != nil {
			return err
		}

		err = appl.Users().Save(ctx, user)
		if err != nil {
			return err
		}

		err = appl.Identities().Save(ctx, identity)
		if err != nil {
			return err
		}

		identity.User = *user

		return nil
	})

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": id.String(),
			"err":         err,
		}, "failed to update user/identity")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if isEmailVerificationNeeded {
		_, err = c.EmailVerificationService.SendVerificationCode(ctx, ctx.RequestData, *identity)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": id.String(),
				"err":         err,
				"username":    identity.Username,
				"email":       user.Email,
			}, "failed to send verification email for update on email")
		}
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

	return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity, true))
}

// UpdateByServiceAccount updates the user by a service account
func (c *UsersController) UpdateByServiceAccount(ctx *app.UpdateByServiceAccountUsersContext) error {
	isSvcAccount := token.IsSpecificServiceAccount(ctx, token.OnlineRegistration)
	if !isSvcAccount {
		log.Error(ctx, nil, "the account is not an authorized service account allowed to update a new user")
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError("account not authorized to update users."))
	}

	var identity *account.Identity
	err := application.Transactional(c.db, func(appl application.Application) error {
		id, err := uuid.FromString(ctx.ID)
		if err != nil {
			return err
		}
		identity, err = appl.Identities().LoadWithUser(ctx, id)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err,
			"identity_id": ctx.ID,
		}, "failed to load identity")
		return jsonapi.JSONErrorResponse(ctx, errors.NewNotFoundError("identity", ctx.ID))
	}
	// We support "deprovisioned" attribute update only for now
	if ctx.Payload != nil && ctx.Payload.Data != nil && ctx.Payload.Data.Attributes != nil && ctx.Payload.Data.Attributes.Deprovisioned != nil {
		user := &identity.User
		user.Deprovisioned = *ctx.Payload.Data.Attributes.Deprovisioned
		err := application.Transactional(c.db, func(appl application.Application) error {
			return appl.Users().Save(ctx, user)
		})
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewInternalErrorFromString(ctx, err.Error()))
		}
	}

	return ctx.OK(ConvertToAppUser(ctx.RequestData, &identity.User, identity, true))
}

func (c *UsersController) updateFeatureLevel(ctx context.Context, user *account.User, updatedFeatureLevel *string) error {
	if log.IsDebug() {
		newFeatureLevel := "<nil>"
		if updatedFeatureLevel != nil {
			newFeatureLevel = *updatedFeatureLevel
		}
		log.Debug(ctx, map[string]interface{}{"current_feature_level": user.FeatureLevel, "new_feature_level": newFeatureLevel}, "updating feature level")
	}
	if updatedFeatureLevel != nil && *updatedFeatureLevel != user.FeatureLevel {
		// handle the case where the value needs to be reset, when the new value is "" (empty string) or "released"
		if *updatedFeatureLevel == "" || *updatedFeatureLevel == account.DefaultFeatureLevel {
			log.Debug(ctx, map[string]interface{}{"user_id": user.ID}, "resetting feature level to %s", account.DefaultFeatureLevel)
			user.FeatureLevel = account.DefaultFeatureLevel
		} else {
			// if the level is 'internal', we need to check against the email address to verify that the user is a Red Hat employee
			if *updatedFeatureLevel == "internal" &&
				// do not allow if email is not verified or if email belongs to another domain
				(!user.EmailVerified || !strings.HasSuffix(user.Email, c.config.GetInternalUsersEmailAddressSuffix())) {
				log.Error(ctx, map[string]interface{}{"user_id": user.ID, "user_email": user.Email}, "user is not an employee")
				return errors.NewForbiddenError("User is not allowed to opt-in for the 'internal' level of features.")
			}
			user.FeatureLevel = *updatedFeatureLevel
		}
	}
	return nil
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
	witURL, err := c.config.GetWITURL(ctx.RequestData)
	if err != nil {
		return err
	}
	return c.RemoteWITService.UpdateWITUser(ctx, request, updateUserPayload, witURL, identityID)
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

func isUsernameUnique(ctx context.Context, appl application.Application, username string, identity account.Identity) (bool, error) {
	usersWithSameUserName, err := appl.Identities().Query(account.IdentityFilterByUsername(username), account.IdentityFilterByProviderType(account.KeycloakIDP))
	if err != nil {
		log.Error(ctx, map[string]interface{}{
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

func isEmailUnique(ctx context.Context, appl application.Application, email string, user account.User) (bool, error) {
	usersWithSameEmail, err := appl.Users().Query(account.UserFilterByEmail(email))
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"email": email,
			"err":   err,
		}, "error fetching users with email filter")
		return false, err
	}
	for _, u := range usersWithSameEmail {
		if u.ID != user.ID {
			return false, nil
		}
	}
	return true, nil
}

func (c *UsersController) userExistsInDB(ctx context.Context, email string, username string) (bool, error) {
	var exists bool
	err := application.Transactional(c.db, func(appl application.Application) error {
		users, err := appl.Users().Query(account.UserFilterByEmail(email))
		if err != nil {
			return err
		}
		if len(users) > 0 {
			// User with the same email exists
			exists = true
			return nil
		}
		identities, err := appl.Identities().Query(account.IdentityFilterByUsername(username), account.IdentityFilterByProviderType(account.KeycloakIDP))
		if err != nil {
			return err
		}
		for _, identity := range identities {
			if identity.UserID.Valid {
				// A Keycloak Identity which is assigned to a user exists
				exists = true
				return nil
			}
		}

		return nil
	})

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"email":    email,
			"username": username,
			"err":      err,
		}, "unable to check if user exists")
	}
	return exists, err
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
				appUser := ConvertToAppUser(ctx.RequestData, &users[i], &identities[i], false)
				appUsers[i] = appUser.Data
			}
			return ctx.OK(&app.UserArray{Data: appUsers})
		})
	})
}

// SendEmailVerificationCode sends out a verification code to the user's email address
func (c *UsersController) SendEmailVerificationCode(ctx *app.SendEmailVerificationCodeUsersContext) error {
	identity, err := login.LoadContextIdentityAndUser(ctx, c.db)
	if err != nil {
		log.Error(ctx, map[string]interface{}{"err": err}, "unable to load identity or user")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	_, err = c.EmailVerificationService.SendVerificationCode(ctx, ctx.RequestData, *identity)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err,
			"identity_id": identity.ID.String(),
			"username":    identity.Username,
			"email":       identity.User.Email,
		}, "failed to send verification email for update on email")
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.NoContent()
}

// VerifyEmail verifies a user's email when updated.
func (c *UsersController) VerifyEmail(ctx *app.VerifyEmailUsersContext) error {
	verifiedCode, err := c.EmailVerificationService.VerifyCode(ctx, ctx.Code)
	var errResponse string
	isVerified := true
	if err != nil {
		errResponse = err.Error()
		isVerified = false
	} else if verifiedCode == nil {
		errResponse = "unable to verify code"
		isVerified = false
	}
	redirectURL, err := rest.AddParam(c.config.GetEmailVerifiedRedirectURL(), "verified", fmt.Sprint(isVerified))
	if err != nil {
		return err
	}
	if errResponse != "" {
		redirectURL, err = rest.AddParam(redirectURL, "error", errResponse)
		if err != nil {
			return err
		}
	}

	if isVerified {
		verfiedUser := verifiedCode.User
		tokenEndpoint, err := c.config.GetKeycloakEndpointToken(ctx.RequestData)
		if err != nil {
			return errors.NewInternalError(ctx, err)
		}
		protectedAccessToken, err := auth.GetProtectedAPIToken(ctx, tokenEndpoint, c.config.GetKeycloakClientID(), c.config.GetKeycloakSecret())
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"keycloak_client_id": c.config.GetKeycloakClientID(),
				"token_endpoint":     tokenEndpoint,
				"err":                err,
			}, "error generating PAT")
			// if there's an error, we are not gonna bother the user
		}

		if protectedAccessToken != "" {
			// try hitting the admin user endpoint only if getting a PAT
			// was successful.

			usersEndpoint, err := c.config.GetKeycloakEndpointUsers(ctx.RequestData)

			identity, err := loadKeyCloakIdentity(c.db, verfiedUser)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"err":     err,
					"user_id": verfiedUser.ID,
				}, "failed to fetch identity for a specific user")
				return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
			}

			keycloakUser := login.KeytcloakUserRequest{
				Username:      &identity.Username,
				Email:         &verfiedUser.Email,
				EmailVerified: &isVerified,
			}

			// not using userProfileService.Update() because it needs a user token
			// and here we don't have one.
			keycloakUserID, _, err := c.userProfileService.CreateOrUpdate(ctx.Context, &keycloakUser, protectedAccessToken, usersEndpoint)
			if err != nil {
				log.Error(ctx, map[string]interface{}{
					"err": err,
				}, "failed to update user's emailVerified attribute in keycloak")
				// we are not gonna bother the user with keycloak errors
			} else {
				log.Info(ctx, map[string]interface{}{
					"keycloak_user_id": *keycloakUserID,
				}, "successfully updated user's emailVerified attribute in keycloak")
			}
		}
	}
	ctx.ResponseData.Header().Set("Location", redirectURL)
	return ctx.TemporaryRedirect()
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
// if isAuthenticated is set to True, then the 'email' field is populated irrespective of whether
// 'emailPrivate' = true/false.
// if isAuthenticated is set of False, then the 'email' field is populated only if
// 'emailPrivate' = false.
func ConvertToAppUser(request *goa.RequestData, user *account.User, identity *account.Identity, isAuthenticated bool) *app.User {
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
	var isEmailPrivate bool
	var createdAt time.Time
	var updatedAt time.Time
	var company string
	var featureLevel string
	var cluster string
	var emailVerified bool
	var contextInformation map[string]interface{}

	if user != nil {
		fullName = user.FullName
		imageURL = user.ImageURL
		bio = user.Bio
		userURL = user.URL
		isEmailPrivate = user.EmailPrivate
		email = user.Email

		if !isAuthenticated && isEmailPrivate {
			email = ""
		}

		company = user.Company
		contextInformation = user.ContextInformation
		cluster = rest.AddTrailingSlashToURL(user.Cluster)
		featureLevel = user.FeatureLevel
		// CreatedAt and UpdatedAt fields in the resulting app.Identity are based on the 'user' entity
		createdAt = user.CreatedAt
		updatedAt = user.UpdatedAt
		emailVerified = user.EmailVerified
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
				EmailPrivate:          &isEmailPrivate,
				Bio:                   &bio,
				URL:                   &userURL,
				UserID:                &userID,
				IdentityID:            &identityID,
				ProviderType:          &providerType,
				Email:                 &email,
				Company:               &company,
				FeatureLevel:          &featureLevel,
				Cluster:               &cluster,
				EmailVerified:         &emailVerified,
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
	relatedURL := rest.AbsoluteURL(request, app.UsersHref(identityID), nil)
	return &app.GenericLinks{
		Self:    &relatedURL,
		Related: &relatedURL,
	}
}

func standardizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

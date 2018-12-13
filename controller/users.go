package controller

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fabric8-services/fabric8-auth/authorization/token"

	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/application/repository"
	"github.com/fabric8-services/fabric8-auth/application/transaction"
	"github.com/fabric8-services/fabric8-auth/authentication/account"
	accountrepo "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authentication/account/service"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

// UsersController implements the users resource.
type UsersController struct {
	*goa.Controller
	app                      application.Application
	config                   UsersControllerConfiguration
	EmailVerificationService service.EmailVerificationService
}

// UsersControllerConfiguration the Configuration for the UsersController
type UsersControllerConfiguration interface {
	GetCacheControlUsers() string
	GetCacheControlUser() string
	GetWITURL() (string, error)
	GetEmailVerifiedRedirectURL() string
	GetInternalUsersEmailAddressSuffix() string
	GetIgnoreEmailInProd() string
	GetOAuthProviderClientID() string
	GetOAuthProviderClientSecret() string
}

// NewUsersController creates a users controller.
func NewUsersController(service *goa.Service, app application.Application, config UsersControllerConfiguration) *UsersController {
	return &UsersController{
		Controller: service.NewController("UsersController"),
		app:        app,
		config:     config,
	}
}

// Show runs the show action.
func (c *UsersController) Show(ctx *app.ShowUsersContext) error {
	tenantSA := token.IsSpecificServiceAccount(ctx, token.Tenant)
	isServiceAccount := tenantSA || token.IsSpecificServiceAccount(ctx, token.Notification)

	var identity *accountrepo.Identity
	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		identityID, err := uuid.FromString(ctx.ID)
		if err != nil {
			return errors.NewBadParameterError("identity_id", ctx.ID)
		}
		identity, err = tr.Identities().LoadWithUser(ctx.Context, identityID)
		if err != nil {
			return err
		}

		if tenantSA && identity.User.Deprovisioned {
			// Don't return deprovisioned users for calls made by Tenant SA
			// TODO we should disable notifications for such users too but if we just return 401 for notification service request we may break it
			ctx.ResponseData.Header().Add("Access-Control-Expose-Headers", "WWW-Authenticate")
			ctx.ResponseData.Header().Set("WWW-Authenticate", "DEPROVISIONED description=\"Account has been deprovisioned\"")
			return errors.NewUnauthorizedError("Account has been deprovisioned")
		}

		return nil
	})
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	return ctx.ConditionalRequest(identity.User, c.config.GetCacheControlUser, func() error {
		return ctx.OK(ConvertToAppUser(ctx.RequestData, &identity.User, identity, isServiceAccount))
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
		user := &accountrepo.User{Email: ctx.Payload.Data.Attributes.Email, Cluster: ctx.Payload.Data.Attributes.Cluster}
		identity := &accountrepo.Identity{Username: ctx.Payload.Data.Attributes.Username, ProviderType: accountrepo.DefaultIDP}
		return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity, true))
	}
	// -----

	userExists, err := c.userExistsInDB(ctx, ctx.Payload.Data.Attributes.Email, ctx.Payload.Data.Attributes.Username)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	if userExists {
		// This may happen for manually deprovisioned users which are reactivating their account via the registration app
		// We should re-deprovision such user
		idn, err := c.app.UserService().IdentityByUsernameAndEmail(ctx, ctx.Payload.Data.Attributes.Username, ctx.Payload.Data.Attributes.Email)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"err":      err,
				"username": ctx.Payload.Data.Attributes.Username,
				"email":    ctx.Payload.Data.Attributes.Email,
			}, "unable to lookup identity by username and email")
			return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
		}
		if idn == nil {
			return jsonapi.JSONErrorResponse(ctx, errors.NewVersionConflictError("user with such email or username already exists"))
		}
		if idn.User.Deprovisioned {
			err := c.app.UserService().ResetDeprovision(ctx, idn.User)
			if err != nil {
				log.Error(ctx, map[string]interface{}{"err": err, "username": ctx.Payload.Data.Attributes.Username, "email": ctx.Payload.Data.Attributes.Email}, "unable to re-provision user")
				return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
			}
		}
		// User/identity already exist. Just return it.
		return ctx.OK(ConvertToAppUser(ctx.RequestData, &idn.User, idn, true))
	}

	// If it's a new user, Auth service generates an Identity ID for the user.
	identityID := uuid.NewV4()
	identity, user, err := c.createUserInDB(ctx, identityID)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"username": identity.Username,
		}, "failed to create user in DB")

		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}

	// finally, if all works, we create a user in WIT too.
	err = c.app.WITService().CreateUser(ctx.Context, identity, identityID.String())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"username": identity.Username,
		}, "failed to create user in WIT")
		// Not a blocker. Log the error and proceed.
	}

	return ctx.OK(ConvertToAppUser(ctx.RequestData, user, identity, true))
}

func (c *UsersController) checkPreviewUser(email string) (bool, error) {
	// Any <username>+preview*@redhat.com email matches
	return regexp.MatchString(c.config.GetIgnoreEmailInProd(), strings.ToLower(email))
}

func (c *UsersController) createUserInDB(ctx *app.CreateUsersContext, identityID uuid.UUID) (*accountrepo.Identity, *accountrepo.User, error) {
	log.Debug(ctx, map[string]interface{}{"identity_id": identityID, "user attributes": ctx.Payload.Data.Attributes}, "creating a new user in DB...")
	userID := uuid.NewV4()
	var err error

	var user *accountrepo.User
	var identity *accountrepo.Identity

	// Mandatory attributes
	// "username", "email", "cluster"

	user = &accountrepo.User{
		ID:            userID,
		Email:         ctx.Payload.Data.Attributes.Email,
		Cluster:       ctx.Payload.Data.Attributes.Cluster,
		EmailPrivate:  false,
		EmailVerified: true,
		FeatureLevel:  accountrepo.DefaultFeatureLevel,
	}
	identity = &accountrepo.Identity{
		ID:           identityID,
		Username:     ctx.Payload.Data.Attributes.Username,
		ProviderType: accountrepo.DefaultIDP, // Ignore Provider Type passed in the payload. We should always use the default
	}

	// associate foreign key
	identity.UserID = accountrepo.NullUUID{UUID: user.ID, Valid: true}

	// Optional Attributes
	identity.RegistrationCompleted = false // Start with 'false', set it to true when user logs in.

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

	returnErrorResponse := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		err = tr.Users().Create(ctx, user)
		if err != nil {
			return err
		}
		err = tr.Identities().Create(ctx, identity)
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

// TODO move business logic to the user service
// Update updates the authorized user based on the provided Token
func (c *UsersController) Update(ctx *app.UpdateUsersContext) error {

	loggedInIdentity, err := c.app.UserService().LoadContextIdentityIfNotDeprovisioned(ctx)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	var isEmailVerificationNeeded bool

	var identity *accountrepo.Identity
	var user *accountrepo.User

	err = transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		identity, err = tr.Identities().Load(ctx, loggedInIdentity.ID)
		if err != nil {
			return errors.NewUnauthorizedError(fmt.Sprintf("auth token contains id %s of unknown Identity\n", loggedInIdentity.ID))
		}

		if identity.UserID.Valid {
			user, err = tr.Users().Load(ctx.Context, identity.UserID.UUID)
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
			isUnique, err := isEmailUnique(ctx, tr, *updatedEmail, *user)
			if err != nil {
				return errs.Wrap(err, fmt.Sprintf("error updating identitity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if !isUnique {
				// TODO: Add errors.NewConflictError(..)
				return errs.Wrap(errors.NewBadParameterError("email", *updatedEmail).Expected("unique email"), fmt.Sprintf("email : %s is already in use", *updatedEmail))
			}
			user.Email = *updatedEmail

			isEmailVerificationNeeded = true
			user.EmailVerified = false
		}

		updatedUserName := ctx.Payload.Data.Attributes.Username
		if updatedUserName != nil && *updatedUserName != identity.Username {
			isValid := isUsernameValid(*updatedUserName)
			if !isValid {
				return errs.Wrap(errors.NewBadParameterError("username", "required"), fmt.Sprintf("invalid value assigned to username for identity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if identity.RegistrationCompleted {
				return errors.NewForbiddenError(fmt.Sprintf("username cannot be updated more than once for identity id %s ", loggedInIdentity.ID))
			}
			isUnique, err := isUsernameUnique(ctx, tr, *updatedUserName, *identity)
			if err != nil {
				return errs.Wrap(err, fmt.Sprintf("error updating identitity with id %s and user with id %s", identity.ID, identity.UserID.UUID))
			}
			if !isUnique {
				// TODO : Add errors.NewConflictError(..)
				return errs.Wrap(errors.NewBadParameterError("username", *updatedUserName).Expected("unique username"), fmt.Sprintf("username : %s is already in use", *updatedUserName))
			}
			identity.Username = *updatedUserName
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
		}
		updatedFullName := ctx.Payload.Data.Attributes.FullName
		if updatedFullName != nil && *updatedFullName != user.FullName {
			*updatedFullName = standardizeSpaces(*updatedFullName)
			user.FullName = *updatedFullName
		}
		updatedImageURL := ctx.Payload.Data.Attributes.ImageURL
		if updatedImageURL != nil && *updatedImageURL != user.ImageURL {
			user.ImageURL = *updatedImageURL

		}
		updateURL := ctx.Payload.Data.Attributes.URL
		if updateURL != nil && *updateURL != user.URL {
			user.URL = *updateURL
		}

		updatedEmailPrivate := ctx.Payload.Data.Attributes.EmailPrivate
		if updatedEmailPrivate != nil {
			user.EmailPrivate = *updatedEmailPrivate
		}

		updatedCompany := ctx.Payload.Data.Attributes.Company
		if updatedCompany != nil && *updatedCompany != user.Company {
			user.Company = *updatedCompany
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

		err = tr.Users().Save(ctx, user)
		if err != nil {
			return err
		}

		err = tr.Identities().Save(ctx, identity)
		if err != nil {
			return err
		}

		identity.User = *user

		return nil
	})

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"identity_id": loggedInIdentity.ID.String(),
			"err":         err,
		}, "failed to update user/identity")
		return jsonapi.JSONErrorResponse(ctx, err)
	}

	if isEmailVerificationNeeded {
		_, err = c.EmailVerificationService.SendVerificationCode(ctx, ctx.RequestData, *identity)
		if err != nil {
			log.Error(ctx, map[string]interface{}{
				"identity_id": loggedInIdentity.ID.String(),
				"err":         err,
				"username":    identity.Username,
				"email":       user.Email,
			}, "failed to send verification email for update on email")
		}
	}

	err = c.updateWITUser(ctx, identity.ID.String())
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

func (c *UsersController) updateFeatureLevel(ctx context.Context, user *accountrepo.User, updatedFeatureLevel *string) error {
	if log.IsDebug() {
		newFeatureLevel := "<nil>"
		if updatedFeatureLevel != nil {
			newFeatureLevel = *updatedFeatureLevel
		}
		log.Debug(ctx, map[string]interface{}{"current_feature_level": user.FeatureLevel, "new_feature_level": newFeatureLevel}, "updating feature level")
	}
	if updatedFeatureLevel != nil && *updatedFeatureLevel != user.FeatureLevel {
		// handle the case where the value needs to be reset, when the new value is "" (empty string) or "released"
		if *updatedFeatureLevel == "" || *updatedFeatureLevel == accountrepo.DefaultFeatureLevel {
			log.Debug(ctx, map[string]interface{}{"user_id": user.ID}, "resetting feature level to %s", accountrepo.DefaultFeatureLevel)
			user.FeatureLevel = accountrepo.DefaultFeatureLevel
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

func (c *UsersController) updateWITUser(ctx *app.UpdateUsersContext, identityID string) error {
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
				URL:                   ctx.Payload.Data.Attributes.URL,
				Username:              ctx.Payload.Data.Attributes.Username,
			},
			Type: ctx.Payload.Data.Type,
		},
	}

	return c.app.WITService().UpdateUser(ctx, updateUserPayload, identityID)
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

func isUsernameUnique(ctx context.Context, repos repository.Repositories, username string, identity accountrepo.Identity) (bool, error) {
	usersWithSameUserName, err := repos.Identities().Query(accountrepo.IdentityFilterByUsername(username), accountrepo.IdentityFilterByProviderType(accountrepo.DefaultIDP))
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

func isEmailUnique(ctx context.Context, repos repository.Repositories, email string, user accountrepo.User) (bool, error) {
	usersWithSameEmail, err := repos.Users().Query(accountrepo.UserFilterByEmail(email))
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
	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		users, err := tr.Users().Query(accountrepo.UserFilterByEmail(email))
		if err != nil {
			return err
		}
		if len(users) > 0 {
			// User with the same email exists
			exists = true
			return nil
		}
		identities, err := tr.Identities().Query(accountrepo.IdentityFilterByUsername(username), accountrepo.IdentityFilterByProviderType(accountrepo.DefaultIDP))
		if err != nil {
			return err
		}
		for _, identity := range identities {
			if identity.UserID.Valid {
				// An auth provider identity which is assigned to a user exists
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
	var users []accountrepo.User
	var identities []accountrepo.Identity
	err := transaction.Transactional(c.app, func(tr transaction.TransactionalResources) error {
		var err error
		users, identities, err = filterUsers(tr, ctx)
		return err
	})
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
}

// SendEmailVerificationCode sends out a verification code to the user's email address
func (c *UsersController) SendEmailVerificationCode(ctx *app.SendEmailVerificationCodeUsersContext) error {
	identity, err := c.app.UserService().LoadContextIdentityAndUser(ctx)
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

	ctx.ResponseData.Header().Set("Location", redirectURL)
	return ctx.TemporaryRedirect()
}

func filterUsers(repos repository.Repositories, ctx *app.ListUsersContext) ([]accountrepo.User, []accountrepo.Identity, error) {
	var err error
	var resultUsers []accountrepo.User
	var resultIdentities []accountrepo.Identity
	/*
		There are 2 database tables we fetch the data from : identities , users
		First, we filter on the attributes of identities table - providerType , username
		After that we use the above result to cumulatively filter on users  - email , company
	*/
	identityFilters := []func(*gorm.DB) *gorm.DB{}
	userFilters := []func(*gorm.DB) *gorm.DB{}
	/*** Start filtering on Identities table ****/
	if ctx.FilterUsername != nil {
		identityFilters = append(identityFilters, accountrepo.IdentityFilterByUsername(*ctx.FilterUsername))
	}
	// Add more filters when needed , here. ..
	if len(identityFilters) != 0 {
		identityFilters = append(identityFilters, accountrepo.IdentityFilterByProviderType(accountrepo.DefaultIDP))
		identityFilters = append(identityFilters, accountrepo.IdentityWithUser())
		// From a data model perspective, we are querying by identity ( and not user )
		filteredIdentities, err := repos.Identities().Query(identityFilters...)
		if err != nil {
			return nil, nil, errs.Wrap(err, "error fetching identities with filter(s)")
		}
		// cumulatively filter out those not matching the user-based filters.
		for _, identity := range filteredIdentities {
			// this is where you keep trying all other filters one by one for 'user' fields like email.
			// If email filter is present then ignore private emails
			if ctx.FilterEmail == nil || (identity.User.Email == *ctx.FilterEmail && !identity.User.EmailPrivate) {
				resultUsers = append(resultUsers, identity.User)
				resultIdentities = append(resultIdentities, identity)
			}
		}
	} else {
		var filteredUsers []accountrepo.User
		/*** Start filtering on Users table ****/
		if ctx.FilterEmail != nil {
			userFilters = append(userFilters, accountrepo.UserFilterByEmail(*ctx.FilterEmail))
			userFilters = append(userFilters, accountrepo.UserFilterByEmailPrivacy(false)) // Ignore users with private emails
		}
		// .. Add other filters in future when needed into the userFilters slice in the above manner.
		if len(userFilters) != 0 {
			filteredUsers, err = repos.Users().Query(userFilters...)
			if err != nil {
				return nil, nil, errs.Wrap(err, "error fetching users")
			}
		} else {
			// Soft-kill the API for listing all Users /api/users
			resultUsers = []accountrepo.User{}
			resultIdentities = []accountrepo.Identity{}
			return resultUsers, resultIdentities, nil
		}
		if err != nil {
			return nil, nil, errs.Wrap(err, "error fetching users")
		}
		resultUsers, resultIdentities, err = loadDefaultIdpIdentities(repos, filteredUsers)
		if err != nil {
			return nil, nil, errs.Wrap(err, "error fetching default IDP identities")
		}
	}
	return resultUsers, resultIdentities, nil
}

// loadDefaultIdpIdentities loads identities for the default IDP users and returns the valid users along with their KC identities
// (if a user is missing his/her KC identity, he/she is filtered out of the result array)
func loadDefaultIdpIdentities(repos repository.Repositories, users []accountrepo.User) ([]accountrepo.User, []accountrepo.Identity, error) {
	var resultUsers []accountrepo.User
	var resultIdentities []accountrepo.Identity
	for _, user := range users {
		identity, err := loadDefaultIdpIdentity(repos, user)
		// if we can't find the default IDP identity
		if err != nil {
			log.Error(nil, map[string]interface{}{"user": user, "err": err}, "unable to load user default IDP identity")
		} else {
			resultUsers = append(resultUsers, user)
			resultIdentities = append(resultIdentities, *identity)
		}
	}
	return resultUsers, resultIdentities, nil
}

func loadDefaultIdpIdentity(repos repository.Repositories, user accountrepo.User) (*accountrepo.Identity, error) {
	identities, err := repos.Identities().Query(accountrepo.IdentityFilterByUserID(user.ID))
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		if identity.ProviderType == accountrepo.DefaultIDP {
			return &identity, nil
		}
	}
	return nil, fmt.Errorf("Can't find Default IDP Identity for user %s", user.Email)
}

// ConvertToAppUser converts a complete Identity object into REST representation
// if isAuthenticated is set to True, then the 'email' field is populated irrespective of whether
// 'emailPrivate' = true/false.
// if isAuthenticated is set of False, then the 'email' field is populated only if
// 'emailPrivate' = false.
func ConvertToAppUser(request *goa.RequestData, user *accountrepo.User, identity *accountrepo.Identity, isAuthenticated bool) *app.User {
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
	var ops []*app.GenericData
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

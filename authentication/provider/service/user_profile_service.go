package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	"io/ioutil"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/authentication/account"
	"github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	errs "github.com/pkg/errors"
)

// OAuthUserProfileClient describes the interface between platform and oauth User profile service.
type userProfileService struct {
	base.BaseService
	client *http.Client
}

// NewUserProfileService creates a new UserProfileService
func NewUserProfileService(context servicecontext.ServiceContext) service.UserProfileService {
	return &userProfileService{
		client: http.DefaultClient,
	}
}

// CreateOrUpdate creates the user in oauth using the admin REST API
// If the user already exists then the user will be updated
// Returns true if a new user has been created and false if the existing user has been updated
func (s *userProfileService) CreateOrUpdate(ctx context.Context,
	oauthUserRequest *provider.OAuthUserRequest, protectedAccessToken string, oauthAdminUserAPIURL string) (*string, bool, error) {
	defaultState := true
	oauthUserRequest.Enabled = &defaultState
	oauthUserRequest.EmailVerified = &defaultState

	body, err := json.Marshal(oauthUserRequest)
	if err != nil {
		return nil, false, errors.NewInternalError(ctx, err)
	}

	req, err := http.NewRequest("POST", oauthAdminUserAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, false, errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := s.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_user_profile_url": oauthAdminUserAPIURL,
			"err": err,
		}, "Unable to create oauth user")
		return nil, false, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
	}

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode != 201 {
		if resp.StatusCode == 409 {
			// User exists. Update the user.
			log.Info(ctx, map[string]interface{}{
				"response_status":        resp.Status,
				"response_body":          bodyString,
				"oauth_user_profile_url": oauthAdminUserAPIURL,
			}, "User already exists in oauth provider. Will try to update")
			createdUserURLString, err := s.updateAsAdmin(ctx, oauthUserRequest, protectedAccessToken, oauthAdminUserAPIURL)
			if err != nil {
				return nil, false, err
			}
			log.Info(ctx, map[string]interface{}{
				"oauth_user_url": oauthAdminUserAPIURL,
				"user_url":       createdUserURLString,
			}, "Successfully updated oauth user")
			return createdUserURLString, false, nil
		}

		log.Error(ctx, map[string]interface{}{
			"response_status":        resp.Status,
			"response_body":          bodyString,
			"oauth_user_profile_url": oauthAdminUserAPIURL,
		}, "Unable to create oauth user")

		// Observed this error code when trying to create user
		// with a token belonging to a different realm.
		if resp.StatusCode == 403 {
			return nil, false, errors.NewUnauthorizedError(bodyString)
		}

		return nil, false, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while creating oauth user :  %s", resp.Status, oauthAdminUserAPIURL))
	}

	createdUserURL, err := resp.Location()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_user_url": oauthAdminUserAPIURL,
			"err":            err,
		}, "Unable to create oauth user")
		return nil, false, errors.NewInternalError(ctx, err)
	}
	if createdUserURL == nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_user_url": oauthAdminUserAPIURL,
		}, "Unable to create oauth user")
		return nil, false, errors.NewInternalError(ctx, errs.Errorf("user creation in oauth might have failed."))
	}

	createdUserURLString := createdUserURL.String()
	log.Info(ctx, map[string]interface{}{
		"oauth_user_url": oauthAdminUserAPIURL,
		"user_url":       createdUserURLString,
	}, "Successfully created oauth user")

	return &createdUserURLString, true, nil
}

func (s *userProfileService) updateAsAdmin(ctx context.Context, userRequest *provider.OAuthUserRequest,
	protectedAccessToken string, adminUserAPIURL string) (*string, error) {
	user, err := s.loadUser(ctx, *userRequest.Username, protectedAccessToken, adminUserAPIURL)
	if err != nil {
		return nil, err
	}
	if user == nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_user_profile_url": adminUserAPIURL,
			"email":                  *userRequest.Email,
		}, "Unable to update oauth user because user not found")
		return nil, errs.New("unable to update oauth user because user not found")
	}
	body, err := json.Marshal(userRequest)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}
	userURL := adminUserAPIURL + "/" + *user.ID
	req, err := http.NewRequest("PUT", userURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := s.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_user_profile_url": adminUserAPIURL,
			"email":                  *userRequest.Email,
			"err":                    err,
		}, "Unable to update oauth user")
		return nil, err
	}
	defer rest.CloseResponse(resp)

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Error(ctx, map[string]interface{}{
			"response_status":        resp.Status,
			"response_body":          bodyString,
			"oauth_user_profile_url": adminUserAPIURL,
			"email":                  *userRequest.Email,
		}, "Unable to update oauth user")

		// new username, but existing email can cause this.
		if resp.StatusCode == 409 {
			return nil, errors.NewVersionConflictError(fmt.Sprintf("user with the same email %s already exists", *userRequest.Email))
		}
		return nil, errs.Errorf("received a non-2xx response %s while creating oauth user:  %s", resp.Status, adminUserAPIURL)
	}
	log.Info(ctx, map[string]interface{}{
		"response_status":        resp.Status,
		"response_body":          bodyString,
		"oauth_user_profile_url": adminUserAPIURL,
		"email":                  *userRequest.Email,
	}, "Successfully updated oauth user")

	return &userURL, nil
}

// loadUser search for a user by username. Return nil if no user found.
func (s *userProfileService) loadUser(ctx context.Context, username string, protectedAccessToken string, adminUserAPIURL string) (*provider.OAuthUserProfile, error) {
	kcURL, err := rest.AddParams(adminUserAPIURL, map[string]string{
		"username": username,
		"first":    "0",
		"max":      "500", // TODO we need to handle big user lists better
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", kcURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := s.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"url": kcURL,
			"err": err,
		}, "Unable to load oauth user")
		return nil, err
	}
	defer rest.CloseResponse(resp)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		bodyString := string(body)
		log.Error(ctx, map[string]interface{}{
			"response_status": resp.Status,
			"response_body":   bodyString,
			"url":             kcURL,
		}, "Unable to load oauth user")

		return nil, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while loading oauth user :  %s", resp.Status, kcURL))
	}

	var users []provider.OAuthUserProfile
	err = json.Unmarshal(body, &users)
	if err != nil {
		return nil, err
	}
	log.Info(ctx, map[string]interface{}{
		"url":              kcURL,
		"user_list_length": len(users),
	}, "users found")
	for _, user := range users {
		if *user.Username == username {
			return &user, nil
		}
	}
	return nil, nil
}

// Update updates the user profile information in oauth provider
func (s *userProfileService) Update(ctx context.Context, userProfile *provider.OAuthUserProfile, accessToken string, profileURL string) error {
	body, err := json.Marshal(userProfile)
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}

	req, err := http.NewRequest("POST", profileURL, bytes.NewReader(body))
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := s.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_user_profile_url": profileURL,
			"err": err,
		}, "Unable to update oauth user profile")
		return errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
	}

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode != http.StatusOK {

		log.Error(ctx, map[string]interface{}{
			"response_status":        resp.Status,
			"response_body":          bodyString,
			"oauth_user_profile_url": profileURL,
		}, "Unable to update oauth user profile")

		if resp.StatusCode == 500 {
			// Observed that a 500 is returned whenever username/email is not unique
			return errors.NewBadParameterError("username or email", fmt.Sprintf("%s , %s", *userProfile.Email, *userProfile.Username))
		}
		if resp.StatusCode == 400 {
			return errors.NewUnauthorizedError(bodyString)
		}

		return errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while updating oauth user profile %s", resp.Status, profileURL))
	}
	log.Info(ctx, map[string]interface{}{
		"response_status":        resp.Status,
		"response_body":          bodyString,
		"oauth_user_profile_url": profileURL,
	}, "Successfully updated oauth user profile")

	return nil
}

//Get gets the user profile information from Oauth provider
func (s *userProfileService) Get(ctx context.Context, accessToken string, profileURL string) (*provider.OAuthUserProfileResponse, error) {

	userProfileResponse := provider.OAuthUserProfileResponse{}

	req, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json, text/plain, */*")

	resp, err := s.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"user_profile_url": profileURL,
			"err":              err,
		}, "Unable to fetch oauth user profile")
		return nil, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
	}

	if resp.StatusCode != http.StatusOK {
		bodyString := rest.ReadBody(resp.Body)
		log.Error(ctx, map[string]interface{}{
			"response_status":  resp.Status,
			"response_body":    bodyString,
			"user_profile_url": profileURL,
		}, "Unable to fetch oauth user profile")
		if resp.StatusCode == 400 {
			return nil, errors.NewUnauthorizedError(bodyString)
		}
		return nil, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while fetching oauth user profile %s", resp.Status, profileURL))
	}

	err = json.NewDecoder(resp.Body).Decode(&userProfileResponse)
	return &userProfileResponse, err
}

func oauthUserRequestFromIdentity(identity repository.Identity) provider.OAuthUserRequest {
	firstName, lastName := account.SplitFullName(identity.User.FullName)
	return provider.OAuthUserRequest{
		Username:      &identity.Username,
		FirstName:     &firstName,
		LastName:      &lastName,
		Email:         &identity.User.Email,
		EmailVerified: &identity.User.EmailVerified,
		Attributes: &provider.OAuthUserProfileAttributes{
			provider.BioAttributeName:      []string{identity.User.Bio},
			provider.ImageURLAttributeName: []string{identity.User.ImageURL},
			provider.URLAttributeName:      []string{identity.User.URL},
			provider.ClusterAttribute:      []string{identity.User.Cluster},
			// Approved=true|false is not stored in the db, but if the program control
			// reaches here, it implies that Approved was true.
			provider.ApprovedAttributeName: []string{"true"},
			provider.CompanyAttributeName:  []string{identity.User.Company},
		},
	}
}

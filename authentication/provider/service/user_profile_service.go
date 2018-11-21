package service

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/application/service"
	"github.com/fabric8-services/fabric8-auth/application/service/base"
	servicecontext "github.com/fabric8-services/fabric8-auth/application/service/context"
	"github.com/fabric8-services/fabric8-auth/authentication/provider"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	errs "github.com/pkg/errors"
)

// userProfileService is the default implementation for UserProfileService
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

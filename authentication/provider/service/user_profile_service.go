package service

import (
	"context"
	"encoding/json"
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

//Get gets the user profile information from Oauth provider
func (s *userProfileService) Get(ctx context.Context, accessToken string, profileURL string) (*provider.OAuthUserProfileResponse, error) {

	userProfileResponse := provider.OAuthUserProfileResponse{}

	req, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		return nil, errors.NewInternalError(err)
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
		return nil, errors.NewInternalError(err)
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
		return nil, errors.NewInternalError(errs.Errorf("received a non-200 response %s while fetching oauth user profile %s", resp.Status, profileURL))
	}

	err = json.NewDecoder(resp.Body).Decode(&userProfileResponse)
	return &userProfileResponse, err
}

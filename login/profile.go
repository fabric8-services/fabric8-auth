package login

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	errs "github.com/pkg/errors"
)

const (
	ImageURLAttributeName = "imageURL"
	BioAttributeName      = "bio"
	URLAttributeName      = "url"
	CompanyAttributeName  = "company"
	ApprovedAttributeName = "approved"
	ClusterAttribute      = "cluster"
	RHDUsernameAttribute  = "rhd_username"
)

// OAuthServiceUserProfile represents standard OAuthService User profile api request payload
type OAuthServiceUserProfile struct {
	ID            *string                            `json:"id,omitempty"`
	CreatedAt     int64                              `json:"createdTimestamp,omitempty"`
	Username      *string                            `json:"username,omitempty"`
	FirstName     *string                            `json:"firstName,omitempty"`
	LastName      *string                            `json:"lastName,omitempty"`
	Email         *string                            `json:"email,omitempty"`
	EmailVerified *bool                              `json:"emailVerified"`
	Attributes    *OAuthServiceUserProfileAttributes `json:"attributes,omitempty"`
}

// OAuthServiceUserProfileAttributes represents standard OAuthService profile payload Attributes
type OAuthServiceUserProfileAttributes map[string][]string

func equalsOAuthServiceAttribute(oauthServiceAttributes OAuthServiceUserProfileAttributes, attribute string, compareTo string) bool {
	if v, ok := oauthServiceAttributes[attribute]; ok {
		if len(v) > 0 {
			if v[0] == compareTo {
				return true
			}
		}
	}
	return false
}

//OAuthServiceUserProfileResponse represents the user profile api response from OAuthService
type OAuthServiceUserProfileResponse struct {
	ID                         *string                            `json:"id"`
	CreatedTimestamp           *int64                             `json:"createdTimestamp"`
	Username                   *string                            `json:"username"`
	Enabled                    *bool                              `json:"enabled"`
	Totp                       *bool                              `json:"totp"`
	EmailVerified              *bool                              `json:"emailVerified"`
	FirstName                  *string                            `json:"firstName"`
	LastName                   *string                            `json:"lastName"`
	Email                      *string                            `json:"email"`
	Attributes                 *OAuthServiceUserProfileAttributes `json:"attributes"`
	DisableableCredentialTypes []*string                          `json:"disableableCredentialTypes"`
	RequiredActions            []interface{}                      `json:"requiredActions"`
}

/*
{"username":"<USERNAME>","enabled":true,"emailVerified":true,
	"firstName":"<FIRST_NAME>","lastName":"<LAST_NAME>",
	"email":"<EMAIL>","attributes":{"approved":["true"],
		"rhd_username":["<USERNAME>"],"company":["<company claim from RHD token>"]}}
*/
type OAuthServiceUserRequest struct {
	Username      *string                            `json:"username"`
	Enabled       *bool                              `json:"enabled"`
	EmailVerified *bool                              `json:"emailVerified"`
	FirstName     *string                            `json:"firstName"`
	LastName      *string                            `json:"lastName"`
	Email         *string                            `json:"email"`
	Attributes    *OAuthServiceUserProfileAttributes `json:"attributes"`
}

// NewOAuthServiceUserProfile creates a new OAuthServiceUserProfile instance.
func NewOAuthServiceUserProfile(firstName *string, lastName *string, email *string, attributes *OAuthServiceUserProfileAttributes) *OAuthServiceUserProfile {
	return &OAuthServiceUserProfile{
		FirstName:  firstName,
		LastName:   lastName,
		Email:      email,
		Attributes: attributes,
	}
}

// UserProfileService describes what the services need to be capable of doing.
type UserProfileService interface {
	Update(ctx context.Context, conOAuthServiceUserProfile *OAuthServiceUserProfile, accessToken string, oauthServiceProfileURL string) error
	Get(ctx context.Context, accessToken string, oauthServiceProfileURL string) (*OAuthServiceUserProfileResponse, error)
	CreateOrUpdate(ctx context.Context, oauthServiceUserRequest *OAuthServiceUserRequest, protectedAccessToken string, oauthServiceAdminUserAPIURL string) (*string, bool, error)
}

// OAuthServiceUserProfileClient describes the interface between platform and OAuthService User profile service.
type OAuthServiceUserProfileClient struct {
	client *http.Client
}

// NewOAuthServiceUserProfileClient creates a new OAuthServiceUserProfileClient
func NewOAuthServiceUserProfileClient() *OAuthServiceUserProfileClient {
	return &OAuthServiceUserProfileClient{
		client: http.DefaultClient,
	}
}

// CreateOrUpdate creates the user in OAuthService using the admin REST API
// If the user already exists then the user will be updated
// Returns true if a new user has been created and false if the existing user has been updated
func (userProfileClient *OAuthServiceUserProfileClient) CreateOrUpdate(ctx context.Context, oauthServiceUserRequest *OAuthServiceUserRequest, protectedAccessToken string, oauthServiceAdminUserAPIURL string) (*string, bool, error) {
	defaultState := true
	oauthServiceUserRequest.Enabled = &defaultState
	oauthServiceUserRequest.EmailVerified = &defaultState

	body, err := json.Marshal(oauthServiceUserRequest)
	if err != nil {
		return nil, false, errors.NewInternalError(ctx, err)
	}

	req, err := http.NewRequest("POST", oauthServiceAdminUserAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, false, errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_service_user_profile_url": oauthServiceAdminUserAPIURL,
			"err": err,
		}, "Unable to create OAuthService user")
		return nil, false, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
	}

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode != 201 {
		if resp.StatusCode == 409 {
			// User exists. Update the user.
			log.Info(ctx, map[string]interface{}{
				"response_status":                resp.Status,
				"response_body":                  bodyString,
				"oauth_service_user_profile_url": oauthServiceAdminUserAPIURL,
			}, "User already exists in OAuthService. Will try to update")
			createdUserURLString, err := userProfileClient.updateAsAdmin(ctx, oauthServiceUserRequest, protectedAccessToken, oauthServiceAdminUserAPIURL)
			if err != nil {
				return nil, false, err
			}
			log.Info(ctx, map[string]interface{}{
				"oauth_service_user_url": oauthServiceAdminUserAPIURL,
				"user_url":               createdUserURLString,
			}, "Successfully updated OAuthService user user")
			return createdUserURLString, false, nil
		}

		log.Error(ctx, map[string]interface{}{
			"response_status":                resp.Status,
			"response_body":                  bodyString,
			"oauth_service_user_profile_url": oauthServiceAdminUserAPIURL,
		}, "Unable to create OAuthService user")

		// Observed this error code when trying to create user
		// with a token belonging to a different realm.
		if resp.StatusCode == 403 {
			return nil, false, errors.NewUnauthorizedError(bodyString)
		}

		return nil, false, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while creating OAuthService user :  %s", resp.Status, oauthServiceAdminUserAPIURL))
	}

	createdUserURL, err := resp.Location()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_service_user_url": oauthServiceAdminUserAPIURL,
			"err": err,
		}, "Unable to create OAuthService user")
		return nil, false, errors.NewInternalError(ctx, err)
	}
	if createdUserURL == nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_service_user_url": oauthServiceAdminUserAPIURL,
		}, "Unable to create OAuthService user")
		return nil, false, errors.NewInternalError(ctx, errs.Errorf("user creation in OAuthService might have failed."))
	}

	createdUserURLString := createdUserURL.String()
	log.Info(ctx, map[string]interface{}{
		"oauth_service_user_url": oauthServiceAdminUserAPIURL,
		"user_url":               createdUserURLString,
	}, "Successfully created OAuthService user")

	return &createdUserURLString, true, nil
}

func (userProfileClient *OAuthServiceUserProfileClient) updateAsAdmin(ctx context.Context, oauthServiceUserRequest *OAuthServiceUserRequest, protectedAccessToken string, oauthServiceAdminUserAPIURL string) (*string, error) {
	user, err := userProfileClient.loadUser(ctx, *oauthServiceUserRequest.Username, protectedAccessToken, oauthServiceAdminUserAPIURL)
	if err != nil {
		return nil, err
	}
	if user == nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_service_user_profile_url": oauthServiceAdminUserAPIURL,
			"email": *oauthServiceUserRequest.Email,
		}, "Unable to update OAuthService user because user not found")
		return nil, errs.New("unable to update OAuthService user because user not found")
	}
	body, err := json.Marshal(oauthServiceUserRequest)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}
	userURL := oauthServiceAdminUserAPIURL + "/" + *user.ID
	req, err := http.NewRequest("PUT", userURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_service_user_profile_url": oauthServiceAdminUserAPIURL,
			"email": *oauthServiceUserRequest.Email,
			"err":   err,
		}, "Unable to update OAuthService user")
		return nil, err
	}
	defer rest.CloseResponse(resp)

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Error(ctx, map[string]interface{}{
			"response_status":                resp.Status,
			"response_body":                  bodyString,
			"oauth_service_user_profile_url": oauthServiceAdminUserAPIURL,
			"email": *oauthServiceUserRequest.Email,
		}, "Unable to update OAuthService user")

		// new username, but existing email can cause this.
		if resp.StatusCode == 409 {
			return nil, errors.NewVersionConflictError(fmt.Sprintf("user with the same email %s already exists", *oauthServiceUserRequest.Email))
		}
		return nil, errs.Errorf("received a non-2xx response %s while creating OAuthService user:  %s", resp.Status, oauthServiceAdminUserAPIURL)
	}
	log.Info(ctx, map[string]interface{}{
		"response_status":                resp.Status,
		"response_body":                  bodyString,
		"oauth_service_user_profile_url": oauthServiceAdminUserAPIURL,
		"email": *oauthServiceUserRequest.Email,
	}, "Successfully updated OAuthService user")

	return &userURL, nil
}

// loadUser search for a user by username. Return nil if no user found.
func (userProfileClient *OAuthServiceUserProfileClient) loadUser(ctx context.Context, username string, protectedAccessToken string, oauthServiceAdminUserAPIURL string) (*OAuthServiceUserProfile, error) {
	kcURL, err := rest.AddParams(oauthServiceAdminUserAPIURL, map[string]string{
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

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"url": kcURL,
			"err": err,
		}, "Unable to load OAuthService user")
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
		}, "Unable to load OAuthService user")

		return nil, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while loading OAuthService user :  %s", resp.Status, kcURL))
	}

	var users []OAuthServiceUserProfile
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

// Update updates the user profile information in OAuthService
func (userProfileClient *OAuthServiceUserProfileClient) Update(ctx context.Context, oauthServiceUserProfile *OAuthServiceUserProfile, accessToken string, oauthServiceProfileURL string) error {
	body, err := json.Marshal(oauthServiceUserProfile)
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}

	req, err := http.NewRequest("POST", oauthServiceProfileURL, bytes.NewReader(body))
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_service_user_profile_url": oauthServiceProfileURL,
			"err": err,
		}, "Unable to update OAuthService user profile")
		return errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
	}

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode != http.StatusOK {

		log.Error(ctx, map[string]interface{}{
			"response_status":                resp.Status,
			"response_body":                  bodyString,
			"oauth_service_user_profile_url": oauthServiceProfileURL,
		}, "Unable to update OAuthService user profile")

		if resp.StatusCode == 500 {
			// Observed that a 500 is returned whenever username/email is not unique
			return errors.NewBadParameterError("username or email", fmt.Sprintf("%s , %s", *oauthServiceUserProfile.Email, *oauthServiceUserProfile.Username))
		}
		if resp.StatusCode == 400 {
			return errors.NewUnauthorizedError(bodyString)
		}

		return errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while updating OAuthService user profile %s", resp.Status, oauthServiceProfileURL))
	}
	log.Info(ctx, map[string]interface{}{
		"response_status":                resp.Status,
		"response_body":                  bodyString,
		"oauth_service_user_profile_url": oauthServiceProfileURL,
	}, "Successfully updated OAuthService user profile")

	return nil
}

//Get gets the user profile information from OAuthService
func (userProfileClient *OAuthServiceUserProfileClient) Get(ctx context.Context, accessToken string, oauthServiceProfileURL string) (*OAuthServiceUserProfileResponse, error) {

	oauthServiceUserProfileResponse := OAuthServiceUserProfileResponse{}

	req, err := http.NewRequest("GET", oauthServiceProfileURL, nil)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json, text/plain, */*")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"oauth_service_user_profile_url": oauthServiceProfileURL,
			"err": err,
		}, "Unable to fetch OAuthService user profile")
		return nil, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
	}

	if resp.StatusCode != http.StatusOK {
		bodyString := rest.ReadBody(resp.Body)
		log.Error(ctx, map[string]interface{}{
			"response_status":                resp.Status,
			"response_body":                  bodyString,
			"oauth_service_user_profile_url": oauthServiceProfileURL,
		}, "Unable to fetch OAuthService user profile")
		if resp.StatusCode == 400 {
			return nil, errors.NewUnauthorizedError(bodyString)
		}
		return nil, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while fetching OAuthService user profile %s", resp.Status, oauthServiceProfileURL))
	}

	err = json.NewDecoder(resp.Body).Decode(&oauthServiceUserProfileResponse)
	return &oauthServiceUserProfileResponse, err
}

func oauthServiceUserRequestFromIdentity(identity repository.Identity) OAuthServiceUserRequest {
	firstName, lastName := account.SplitFullName(identity.User.FullName)
	return OAuthServiceUserRequest{
		Username:      &identity.Username,
		FirstName:     &firstName,
		LastName:      &lastName,
		Email:         &identity.User.Email,
		EmailVerified: &identity.User.EmailVerified,
		Attributes: &OAuthServiceUserProfileAttributes{
			BioAttributeName:      []string{identity.User.Bio},
			ImageURLAttributeName: []string{identity.User.ImageURL},
			URLAttributeName:      []string{identity.User.URL},
			ClusterAttribute:      []string{identity.User.Cluster},
			// Approved=true|false is not stored in the db, but if the program control
			// reaches here, it implies that Approved was true.
			ApprovedAttributeName: []string{"true"},
			CompanyAttributeName:  []string{identity.User.Company},
		},
	}
}

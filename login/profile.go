package login

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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

// KeycloakUserProfile represents standard Keycloak User profile api request payload
type KeycloakUserProfile struct {
	ID         *string                        `json:"id,omitempty"`
	CreatedAt  int64                          `json:"createdTimestamp,omitempty"`
	Username   *string                        `json:"username,omitempty"`
	FirstName  *string                        `json:"firstName,omitempty"`
	LastName   *string                        `json:"lastName,omitempty"`
	Email      *string                        `json:"email,omitempty"`
	Attributes *KeycloakUserProfileAttributes `json:"attributes,omitempty"`
}

// KeycloakUserProfileAttributes represents standard Keycloak profile payload Attributes
type KeycloakUserProfileAttributes map[string][]string

//KeycloakUserProfileResponse represents the user profile api response from keycloak
type KeycloakUserProfileResponse struct {
	ID                         *string                        `json:"id"`
	CreatedTimestamp           *int64                         `json:"createdTimestamp"`
	Username                   *string                        `json:"username"`
	Enabled                    *bool                          `json:"enabled"`
	Totp                       *bool                          `json:"totp"`
	EmailVerified              *bool                          `json:"emailVerified"`
	FirstName                  *string                        `json:"firstName"`
	LastName                   *string                        `json:"lastName"`
	Email                      *string                        `json:"email"`
	Attributes                 *KeycloakUserProfileAttributes `json:"attributes"`
	DisableableCredentialTypes []*string                      `json:"disableableCredentialTypes"`
	RequiredActions            []interface{}                  `json:"requiredActions"`
}

/*
{"username":"<USERNAME>","enabled":true,"emailVerified":true,
	"firstName":"<FIRST_NAME>","lastName":"<LAST_NAME>",
	"email":"<EMAIL>","attributes":{"approved":["true"],
		"rhd_username":["<USERNAME>"],"company":["<company claim from RHD token>"]}}
*/
type KeytcloakUserRequest struct {
	Username      *string                        `json:"username"`
	Enabled       *bool                          `json:"enabled"`
	EmailVerified *bool                          `json:"emailVerified"`
	FirstName     *string                        `json:"firstName"`
	LastName      *string                        `json:"lastName"`
	Email         *string                        `json:"email"`
	Attributes    *KeycloakUserProfileAttributes `json:"attributes"`
}

// NewKeycloakUserProfile creates a new keycloakUserProfile instance.
func NewKeycloakUserProfile(firstName *string, lastName *string, email *string, attributes *KeycloakUserProfileAttributes) *KeycloakUserProfile {
	return &KeycloakUserProfile{
		FirstName:  firstName,
		LastName:   lastName,
		Email:      email,
		Attributes: attributes,
	}
}

// UserProfileService describes what the services need to be capable of doing.
type UserProfileService interface {
	Update(ctx context.Context, conkeycloakUserProfile *KeycloakUserProfile, accessToken string, keycloakProfileURL string) error
	Get(ctx context.Context, accessToken string, keycloakProfileURL string) (*KeycloakUserProfileResponse, error)
	Create(ctx context.Context, keycloakUserRequest *KeytcloakUserRequest, protectedAccessToken string, keycloakAdminUserAPIURL string) (*string, error)
}

// KeycloakUserProfileClient describes the interface between platform and Keycloak User profile service.
type KeycloakUserProfileClient struct {
	client *http.Client
}

// NewKeycloakUserProfileClient creates a new KeycloakUserProfileClient
func NewKeycloakUserProfileClient() *KeycloakUserProfileClient {
	return &KeycloakUserProfileClient{
		client: http.DefaultClient,
	}
}

// Create creates the user in Keycloak using the admin REST API
func (userProfileClient *KeycloakUserProfileClient) Create(ctx context.Context, keycloakUserRequest *KeytcloakUserRequest, protectedAccessToken string, keycloakAdminUserAPIURL string) (*string, error) {
	body, err := json.Marshal(keycloakUserRequest)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}

	req, err := http.NewRequest("POST", keycloakAdminUserAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_profile_url": keycloakAdminUserAPIURL,
			"err": err,
		}, "Unable to create Keycloak user")
		return nil, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer resp.Body.Close()
	}

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode != 201 {

		log.Error(ctx, map[string]interface{}{
			"response_status":           resp.Status,
			"response_body":             bodyString,
			"keycloak_user_profile_url": keycloakAdminUserAPIURL,
		}, "Unable to create Keycloak user")

		// Observed this error code when trying to create user
		// with a token belonging to a different realm.
		if resp.StatusCode == 403 {
			return nil, errors.NewUnauthorizedError(bodyString)
		}

		// Observed this error code when trying to create user with an existing username.
		if resp.StatusCode == 409 {
			// This isn't version conflict really,
			// but helps us generate the final response code.
			return nil, errors.NewVersionConflictError(fmt.Sprintf("user with username %s / email %s already exists", *keycloakUserRequest.Username, *keycloakUserRequest.Email))
		}

		return nil, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while creating keycloak user :  %s", resp.Status, keycloakAdminUserAPIURL))
	}
	log.Info(ctx, map[string]interface{}{
		"response_status":           resp.Status,
		"response_body":             bodyString,
		"keycloak_user_profile_url": keycloakAdminUserAPIURL,
	}, "Successfully create Keycloak user")

	createdUserURL, err := resp.Location()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_url": keycloakAdminUserAPIURL,
			"err":               err,
		}, "Unable to create Keycloak user")
		return nil, errors.NewInternalError(ctx, err)
	}
	if createdUserURL == nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_url": keycloakAdminUserAPIURL,
		}, "Unable to create Keycloak user")
		return nil, errors.NewInternalError(ctx, errs.Errorf("user creation in keycloak might have failed."))
	}

	createdUserURLString := createdUserURL.String()
	log.Info(ctx, map[string]interface{}{
		"keycloak_user_url": keycloakAdminUserAPIURL,
		"user_url":          createdUserURLString,
	}, "Successfully created Keycloak user user")

	return &createdUserURLString, nil
}

// Update updates the user profile information in Keycloak
func (userProfileClient *KeycloakUserProfileClient) Update(ctx context.Context, keycloakUserProfile *KeycloakUserProfile, accessToken string, keycloakProfileURL string) error {
	body, err := json.Marshal(keycloakUserProfile)
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}

	req, err := http.NewRequest("POST", keycloakProfileURL, bytes.NewReader(body))
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_profile_url": keycloakProfileURL,
			"err": err,
		}, "Unable to update Keycloak user profile")
		return errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer resp.Body.Close()
	}

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode != http.StatusOK {

		log.Error(ctx, map[string]interface{}{
			"response_status":           resp.Status,
			"response_body":             bodyString,
			"keycloak_user_profile_url": keycloakProfileURL,
		}, "Unable to update Keycloak user profile")

		if resp.StatusCode == 500 {
			// Observed that a 500 is returned whenever username/email is not unique
			return errors.NewBadParameterError("username or email", fmt.Sprintf("%s , %s", *keycloakUserProfile.Email, *keycloakUserProfile.Username))
		}
		if resp.StatusCode == 400 {
			return errors.NewUnauthorizedError(bodyString)
		}

		return errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while updating keycloak user profile %s", resp.Status, keycloakProfileURL))
	}
	log.Info(ctx, map[string]interface{}{
		"response_status":           resp.Status,
		"response_body":             bodyString,
		"keycloak_user_profile_url": keycloakProfileURL,
	}, "Successfully updated Keycloak user profile")

	return nil
}

//Get gets the user profile information from Keycloak
func (userProfileClient *KeycloakUserProfileClient) Get(ctx context.Context, accessToken string, keycloakProfileURL string) (*KeycloakUserProfileResponse, error) {

	keycloakUserProfileResponse := KeycloakUserProfileResponse{}

	req, err := http.NewRequest("GET", keycloakProfileURL, nil)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json, text/plain, */*")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_profile_url": keycloakProfileURL,
			"err": err,
		}, "Unable to fetch Keycloak user profile")
		return nil, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		bodyString := rest.ReadBody(resp.Body)
		log.Error(ctx, map[string]interface{}{
			"response_status":           resp.Status,
			"response_body":             bodyString,
			"keycloak_user_profile_url": keycloakProfileURL,
		}, "Unable to fetch Keycloak user profile")
		if resp.StatusCode == 400 {
			return nil, errors.NewUnauthorizedError(bodyString)
		}
		return nil, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while fetching keycloak user profile %s", resp.Status, keycloakProfileURL))
	}

	err = json.NewDecoder(resp.Body).Decode(&keycloakUserProfileResponse)
	return &keycloakUserProfileResponse, err
}

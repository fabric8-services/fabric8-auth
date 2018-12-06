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

// KeycloakUserProfile represents standard Keycloak User profile api request payload
type KeycloakUserProfile struct {
	ID            *string                        `json:"id,omitempty"`
	CreatedAt     int64                          `json:"createdTimestamp,omitempty"`
	Username      *string                        `json:"username,omitempty"`
	FirstName     *string                        `json:"firstName,omitempty"`
	LastName      *string                        `json:"lastName,omitempty"`
	Email         *string                        `json:"email,omitempty"`
	EmailVerified *bool                          `json:"emailVerified"`
	Attributes    *KeycloakUserProfileAttributes `json:"attributes,omitempty"`
}

// KeycloakUserProfileAttributes represents standard Keycloak profile payload Attributes
type KeycloakUserProfileAttributes map[string][]string

func equalsKeycloakAttribute(keycloakAttributes KeycloakUserProfileAttributes, attribute string, compareTo string) bool {
	if v, ok := keycloakAttributes[attribute]; ok {
		if len(v) > 0 {
			if v[0] == compareTo {
				return true
			}
		}
	}
	return false
}

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
type KeycloakUserRequest struct {
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
	CreateOrUpdate(ctx context.Context, keycloakUserRequest *KeycloakUserRequest, protectedAccessToken string, keycloakAdminUserAPIURL string) (*string, bool, error)
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

// CreateOrUpdate creates the user in Keycloak using the admin REST API
// If the user already exists then the user will be updated
// Returns true if a new user has been created and false if the existing user has been updated
func (userProfileClient *KeycloakUserProfileClient) CreateOrUpdate(ctx context.Context, keycloakUserRequest *KeycloakUserRequest, protectedAccessToken string, keycloakAdminUserAPIURL string) (*string, bool, error) {
	defaultState := true
	keycloakUserRequest.Enabled = &defaultState
	keycloakUserRequest.EmailVerified = &defaultState

	body, err := json.Marshal(keycloakUserRequest)
	if err != nil {
		return nil, false, errors.NewInternalError(ctx, err)
	}

	req, err := http.NewRequest("POST", keycloakAdminUserAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, false, errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_profile_url": keycloakAdminUserAPIURL,
			"err":                       err,
		}, "Unable to create Keycloak user")
		return nil, false, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
	}

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode != 201 {
		if resp.StatusCode == 409 {
			// User exists. Update the user.
			log.Info(ctx, map[string]interface{}{
				"response_status":           resp.Status,
				"response_body":             bodyString,
				"keycloak_user_profile_url": keycloakAdminUserAPIURL,
			}, "User already exists in Keycloak. Will try to update")
			createdUserURLString, err := userProfileClient.updateAsAdmin(ctx, keycloakUserRequest, protectedAccessToken, keycloakAdminUserAPIURL)
			if err != nil {
				return nil, false, err
			}
			log.Info(ctx, map[string]interface{}{
				"keycloak_user_url": keycloakAdminUserAPIURL,
				"user_url":          createdUserURLString,
			}, "Successfully updated Keycloak user user")
			return createdUserURLString, false, nil
		}

		log.Error(ctx, map[string]interface{}{
			"response_status":           resp.Status,
			"response_body":             bodyString,
			"keycloak_user_profile_url": keycloakAdminUserAPIURL,
		}, "Unable to create Keycloak user")

		// Observed this error code when trying to create user
		// with a token belonging to a different realm.
		if resp.StatusCode == 403 {
			return nil, false, errors.NewUnauthorizedError(bodyString)
		}

		return nil, false, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while creating keycloak user :  %s", resp.Status, keycloakAdminUserAPIURL))
	}

	createdUserURL, err := resp.Location()
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_url": keycloakAdminUserAPIURL,
			"err":               err,
		}, "Unable to create Keycloak user")
		return nil, false, errors.NewInternalError(ctx, err)
	}
	if createdUserURL == nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_url": keycloakAdminUserAPIURL,
		}, "Unable to create Keycloak user")
		return nil, false, errors.NewInternalError(ctx, errs.Errorf("user creation in keycloak might have failed."))
	}

	createdUserURLString := createdUserURL.String()
	log.Info(ctx, map[string]interface{}{
		"keycloak_user_url": keycloakAdminUserAPIURL,
		"user_url":          createdUserURLString,
	}, "Successfully created Keycloak user")

	return &createdUserURLString, true, nil
}

func (userProfileClient *KeycloakUserProfileClient) updateAsAdmin(ctx context.Context, keycloakUserRequest *KeycloakUserRequest, protectedAccessToken string, keycloakAdminUserAPIURL string) (*string, error) {
	user, err := userProfileClient.loadUser(ctx, *keycloakUserRequest.Username, protectedAccessToken, keycloakAdminUserAPIURL)
	if err != nil {
		return nil, err
	}
	if user == nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_profile_url": keycloakAdminUserAPIURL,
			"email":                     *keycloakUserRequest.Email,
		}, "Unable to update Keycloak user because user not found")
		return nil, errs.New("unable to update Keycloak user because user not found")
	}
	body, err := json.Marshal(keycloakUserRequest)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}
	userURL := keycloakAdminUserAPIURL + "/" + *user.ID
	req, err := http.NewRequest("PUT", userURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := userProfileClient.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_user_profile_url": keycloakAdminUserAPIURL,
			"email":                     *keycloakUserRequest.Email,
			"err":                       err,
		}, "Unable to update Keycloak user")
		return nil, err
	}
	defer rest.CloseResponse(resp)

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Error(ctx, map[string]interface{}{
			"response_status":           resp.Status,
			"response_body":             bodyString,
			"keycloak_user_profile_url": keycloakAdminUserAPIURL,
			"email":                     *keycloakUserRequest.Email,
		}, "Unable to update Keycloak user")

		// new username, but existing email can cause this.
		if resp.StatusCode == 409 {
			return nil, errors.NewVersionConflictError(fmt.Sprintf("user with the same email %s already exists", *keycloakUserRequest.Email))
		}
		return nil, errs.Errorf("received a non-2xx response %s while creating keycloak user:  %s", resp.Status, keycloakAdminUserAPIURL)
	}
	log.Info(ctx, map[string]interface{}{
		"response_status":           resp.Status,
		"response_body":             bodyString,
		"keycloak_user_profile_url": keycloakAdminUserAPIURL,
		"email":                     *keycloakUserRequest.Email,
	}, "Successfully updated Keycloak user")

	return &userURL, nil
}

// loadUser search for a user by username. Return nil if no user found.
func (userProfileClient *KeycloakUserProfileClient) loadUser(ctx context.Context, username string, protectedAccessToken string, keycloakAdminUserAPIURL string) (*KeycloakUserProfile, error) {
	kcURL, err := rest.AddParams(keycloakAdminUserAPIURL, map[string]string{
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
		}, "Unable to load Keycloak user")
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
		}, "Unable to load Keycloak user")

		return nil, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while loading keycloak user :  %s", resp.Status, kcURL))
	}

	var users []KeycloakUserProfile
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
			"err":                       err,
		}, "Unable to update Keycloak user profile")
		return errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
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
			"err":                       err,
		}, "Unable to fetch Keycloak user profile")
		return nil, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer rest.CloseResponse(resp)
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

func keycloakUserRequestFromIdentity(identity repository.Identity) KeycloakUserRequest {
	firstName, lastName := account.SplitFullName(identity.User.FullName)
	return KeycloakUserRequest{
		Username:      &identity.Username,
		FirstName:     &firstName,
		LastName:      &lastName,
		Email:         &identity.User.Email,
		EmailVerified: &identity.User.EmailVerified,
		Attributes: &KeycloakUserProfileAttributes{
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

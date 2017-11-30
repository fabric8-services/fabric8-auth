package link

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	errs "github.com/pkg/errors"
)

/*
{"identityProvider":"rhd","userId":"<USER_ID>","userName":"<USERNAME>"}
*/

// KeycloakLinkIDPRequest represents standard Keycloak User profile api request payload
type KeycloakLinkIDPRequest struct {
	IdentityProvider *string `json:"identityProvider,omitempty"`
	UserID           *string `json:"userId,omitempty"`
	Username         *string `json:"userName,omitempty"`
}

// KeycloakIDPService describes what the services need to be capable of doing.
type KeycloakIDPService interface {
	Create(ctx context.Context, keycloakLinkIDPRequest *KeycloakLinkIDPRequest, protectedAccessToken string, keycloakIDPLinkURL string) error
}

// KeycloakIDPServiceClient describes the interface between platform and Keycloak User profile service.
type KeycloakIDPServiceClient struct {
	client *http.Client
}

// NewKeycloakIDPServiceClient creates a new Keycloakc
func NewKeycloakIDPServiceClient() *KeycloakIDPServiceClient {
	return &KeycloakIDPServiceClient{
		client: http.DefaultClient,
	}
}

// Create creates the IDP link in Keycloak using the admin REST API
func (c *KeycloakIDPServiceClient) Create(ctx context.Context, keycloakLinkIDPRequest *KeycloakLinkIDPRequest, protectedAccessToken string, keycloakIDPLinkURL string) error {
	body, err := json.Marshal(keycloakLinkIDPRequest)
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}

	req, err := http.NewRequest("POST", keycloakIDPLinkURL, bytes.NewReader(body))
	if err != nil {
		return errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+protectedAccessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.client.Do(req)

	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"keycloak_idp_link_url": keycloakIDPLinkURL,
			"err": err,
		}, "Unable to create idp link for RHD")
		return errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer resp.Body.Close()
	}

	bodyString := rest.ReadBody(resp.Body)
	if resp.StatusCode != 204 {
		log.Error(ctx, map[string]interface{}{
			"response_status":       resp.Status,
			"response_body":         bodyString,
			"keycloak_idp_link_url": keycloakIDPLinkURL,
		}, "Unable to create idp link for RHD")

		// Observed this error code when trying to create user
		// with a token belonging to a different realm.
		if resp.StatusCode == 403 {
			return errors.NewUnauthorizedError(bodyString)
		}

		return errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while creating keycloak user :  %s", resp.Status, keycloakIDPLinkURL))
	}
	log.Info(ctx, map[string]interface{}{
		"response_status":       resp.Status,
		"response_body":         bodyString,
		"keycloak_idp_link_url": keycloakIDPLinkURL,
	}, "Successfully created RHD link for Keycloak user")

	return nil
}

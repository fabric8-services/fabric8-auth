package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	errs "github.com/pkg/errors"
)

// KeycloakExternalTokenResponse represents standard Keycloak external token response payload
type KeycloakExternalTokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
}

type TokenAppResponse interface {
	ToParameterString() string
	ToJSONString() (string, error)
}

func ToParameterString(r KeycloakExternalTokenResponse) string {
	//access_token=f75c6_token_ceea0&scope=admin%3Arepo_hook%2Cgist%2Cread%3Aorg%2Crepo%2Cuser&token_type=bearer
	return fmt.Sprintf("access_token=%s&scope=%s&token_type=%s", r.AccessToken, r.Scope, r.TokenType)
}

func ToJSONString(r KeycloakExternalTokenResponse) (string, error) {
	jsonByte, err := json.Marshal(r)
	return string(jsonByte), err
}

// KeycloakExternalTokenService describes what the services need to be capable of doing.
type KeycloakExternalTokenService interface {
	Get(ctx context.Context, accessToken string, keycloakExternalTokenURL string) (*KeycloakExternalTokenResponse, error)
}

// KeycloakExternalTokenServiceClient describes the interface between platform and Keycloak token service.
type KeycloakExternalTokenServiceClient struct {
	client *http.Client
}

// NewKeycloakTokenServiceClient creates a new KeycloakTokenServiceClient
func NewKeycloakTokenServiceClient() *KeycloakExternalTokenServiceClient {
	return &KeycloakExternalTokenServiceClient{
		client: http.DefaultClient,
	}
}

//Get gets the external token information from Keycloak
func (keycloakExternalTokenServiceClient *KeycloakExternalTokenServiceClient) Get(ctx context.Context, accessToken string, keycloakExternalTokenURL string) (*KeycloakExternalTokenResponse, error) {

	keycloakExternalTokenResponse := KeycloakExternalTokenResponse{}

	req, err := http.NewRequest("GET", keycloakExternalTokenURL, nil)
	if err != nil {
		return nil, errors.NewInternalError(ctx, err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json, text/plain, */*")

	resp, err := keycloakExternalTokenServiceClient.client.Do(req)

	if err != nil {
		log.Error(nil, map[string]interface{}{
			"keycloak_external_token_url": keycloakExternalTokenURL,
			"err": err,
		}, "Unable to fetch external keycloak token")
		return nil, errors.NewInternalError(ctx, err)
	} else if resp != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		log.Error(nil, map[string]interface{}{
			"response_status":             resp.Status,
			"response_body":               rest.ReadBody(resp.Body),
			"keycloak_external_token_url": keycloakExternalTokenURL,
		}, "Unable to fetch external keycloak token")
		if resp.StatusCode == 400 {
			return nil, errors.NewUnauthorizedError(rest.ReadBody(resp.Body))
		}
		return nil, errors.NewInternalError(ctx, errs.Errorf("received a non-200 response %s while fetching keycloak external token %s", resp.Status, keycloakExternalTokenURL))
	}
	if strings.Contains(keycloakExternalTokenURL, "openshift-v3") {
		err = json.NewDecoder(resp.Body).Decode(&keycloakExternalTokenResponse)
	} else {

		// The format for github response is
		// access_token=f75c6_token_ceea0&scope=admin%3Arepo_hook%2Cgist%2Cread%3Aorg%2Crepo%2Cuser&token_type=bearer
		// wish there was some other way to do this!

		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		allParamsValues := strings.Split(bodyString, "&")
		for _, pvString := range allParamsValues {
			pv := strings.Split(pvString, "=")
			if pv[0] == "access_token" {
				keycloakExternalTokenResponse.AccessToken = pv[1]
			}
			if pv[0] == "token_type" {
				keycloakExternalTokenResponse.TokenType = pv[1]
			}
			if pv[0] == "scope" {
				keycloakExternalTokenResponse.Scope = pv[1]
			}
			// "expires_in" is not present for github
		}
	}
	return &keycloakExternalTokenResponse, err
}

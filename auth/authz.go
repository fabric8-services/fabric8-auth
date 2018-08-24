package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/fabric8-services/fabric8-auth/token"

	errs "github.com/pkg/errors"
)

// UserInfo represents a user info oauth service payload
type UserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Email             string `json:"email"`
}

// GetUserInfo gets user info from oauth service
func GetUserInfo(ctx context.Context, userInfoEndpoint string, userAccessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "unable to create http request")
		return nil, errors.NewInternalError(ctx, errs.Wrap(err, "unable to create http request"))
	}
	req.Header.Add("Authorization", "Bearer "+userAccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "unable to get user info from oauth service")
		return nil, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get user info from oauth service"))
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body)
	if res.StatusCode != http.StatusOK {
		log.Error(ctx, map[string]interface{}{
			"response_body":   bodyString,
			"response_status": res.Status,
		}, "unable to get user info from oauth service")
		return nil, errors.NewInternalError(ctx, errs.New("unable to get user info from oauth service. Response status: "+res.Status+". Response body: "+bodyString))
	}

	var r UserInfo
	err = json.Unmarshal([]byte(bodyString), &r)
	if err != nil {
		return nil, errors.NewInternalError(ctx, errs.Wrapf(err, "error when unmarshal json with user info payload: \"%s\" ", bodyString))
	}

	return &r, nil
}

// ValidateOAuthServiceUser returns true if the user exists in oauth service. Returns false if the user is not found
func ValidateOAuthServiceUser(ctx context.Context, adminEndpoint string, userID, protectionAPIToken string) (bool, error) {
	req, err := http.NewRequest("GET", adminEndpoint+"/users/"+userID, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "unable to create http request")
		return false, errors.NewInternalError(ctx, errs.Wrap(err, "unable to create http request"))
	}
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"user_id": userID,
			"err":     err.Error(),
		}, "unable to get user from oauth service")
		return false, errors.NewInternalError(ctx, errs.Wrap(err, "unable to get user from oauth service"))
	}
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body) // To prevent FDs leaks
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		log.Error(ctx, map[string]interface{}{
			"user_id":         userID,
			"response_body":   bodyString,
			"response_status": res.Status,
		}, "unable to get user from oauth service")
		return false, errors.NewInternalError(ctx, errs.New("unable to get user from oauth service. Response status: "+res.Status+". Response body: "+bodyString))
	}
}

// GetProtectedAPIToken obtains a Protected API Token (PAT) from oauth service
func GetProtectedAPIToken(ctx context.Context, openidConnectTokenURL string, clientID string, clientSecret string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.PostForm(openidConnectTokenURL, url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
	})
	if err != nil {
		return "", errors.NewInternalError(ctx, errs.Wrap(err, "error when obtaining token"))
	}
	defer rest.CloseResponse(res)
	switch res.StatusCode {
	case http.StatusOK:
		// OK
	case http.StatusUnauthorized:
		return "", errors.NewUnauthorizedError(res.Status + " " + rest.ReadBody(res.Body))
	case http.StatusBadRequest:
		return "", errors.NewBadParameterError(rest.ReadBody(res.Body), nil)
	default:
		return "", errors.NewInternalError(ctx, errs.New(res.Status+" "+rest.ReadBody(res.Body)))
	}

	t, err := token.ReadTokenSet(ctx, res)
	if err != nil {
		return "", err
	}
	return *t.AccessToken, nil
}

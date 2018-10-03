package provider

import (
	"context"
	"encoding/json"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	"github.com/satori/go.uuid"
	netcontext "golang.org/x/net/context"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
)

// UserProfile represents a user profile fetched from Identity Provider
type UserProfile struct {
	Name          string
	Username      string
	GivenName     string
	FamilyName    string
	Email         string
	EmailVerified bool
	Company       string
	Approved      bool
	Subject       string
}

type IdentityProviderResponse struct {
	Username      string `json:"preferred_username"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Company       string `json:"company"`
	Approved      bool   `json:"approved"`
	Subject       string `json:"sub"`
}

// OauthConfig represents OAuth2 config
type OauthConfig interface {
	Exchange(ctx netcontext.Context, code string) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
}

// OauthIdentityProvider is an implementation of Identity Provider
type OAuthIdentityProvider struct {
	oauth2.Config
	ProviderID uuid.UUID
	ScopeStr   string
	ProfileURL string
}

// Profile fetches a user profile from the Identity Provider
func (provider *OAuthIdentityProvider) Profile(ctx context.Context, token oauth2.Token) (*UserProfile, error) {
	body, err := provider.UserProfilePayload(ctx, token)
	if err != nil {
		return nil, err
	}
	var u UserProfile
	var idpResponse IdentityProviderResponse
	err = json.Unmarshal(body, &idpResponse)
	if err != nil {
		return nil, err
	}

	u = UserProfile{
		Username:      idpResponse.Username,
		GivenName:     idpResponse.GivenName,
		FamilyName:    idpResponse.FamilyName,
		Email:         idpResponse.Email,
		EmailVerified: idpResponse.EmailVerified,
		Company:       idpResponse.Company,
		Approved:      idpResponse.Approved,
		Subject:       idpResponse.Subject,
	}
	return &u, nil
}

// UserProfilePayload fetches user profile payload from Identity Provider
func (provider *OAuthIdentityProvider) UserProfilePayload(ctx context.Context, token oauth2.Token) ([]byte, error) {
	req, err := http.NewRequest("GET", provider.ProfileURL, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"profile_url": provider.ProfileURL,
		}, "unable to create http request")
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"profile_url": provider.ProfileURL,
		}, "unable to get user profile")
		return nil, err
	}
	defer rest.CloseResponse(res)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":         err.Error(),
			"profile_url": provider.ProfileURL,
		}, "unable to read user profile payload")
		return body, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		log.Error(ctx, map[string]interface{}{
			"status":        res.Status,
			"response_body": string(body),
			"profile_url":   provider.ProfileURL,
		}, "unable to get user profile")
		return nil, errors.NewInternalErrorFromString(ctx, "unable to get user profile")
	}
	return body, nil
}

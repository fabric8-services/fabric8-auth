package login

import (
	"context"
	"encoding/json"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"golang.org/x/oauth2"
)

type LoginIdentityProvider struct {
	oauth.OauthIdentityProvider
}

/*
Sample response:

{\"sub\":\"837f2447-2e42-4db9-9f32-817d4866178a\",\"approved\":true,\"email_verified\":true,\"name\":\"Shoubhik Bose\",\"company\":\"red hat\",\"preferred_username\":\"shbose\",\"given_name\":\"Shoubhik\",\"family_name\":\"Bose\",\"email\":\"sbose0708@gmail.com\"}
*/

type loginIdentityProviderResponse struct {
	Username      string `json:"preferred_username"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Company       string `json:"company"`
	Approved      bool   `json:"approved"`
	Subject       string `json:"subject"`
}

func NewLoginIdentityProvider(config Configuration) *LoginIdentityProvider {
	provider := &LoginIdentityProvider{}
	// initialize oauth too here ?
	provider.ProfileURL = config.GetUserInfoEndpoint()
	return provider
}

// Profile fetches a user profile from the Identity Provider
func (provider *LoginIdentityProvider) Profile(ctx context.Context, token oauth2.Token) (*oauth.UserProfile, error) {
	body, err := provider.UserProfilePayload(ctx, token)
	if err != nil {
		return nil, err
	}
	var u oauth.UserProfile
	var idpResponse loginIdentityProviderResponse
	err = json.Unmarshal(body, &idpResponse)
	if err != nil {
		return nil, err
	}

	u = oauth.UserProfile{
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

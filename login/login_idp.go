package login

import (
	"context"
	"encoding/json"
	"github.com/fabric8-services/fabric8-auth/token/oauth"
	"golang.org/x/oauth2"
)

type IdentityProvider struct {
	oauth.OAuthIdentityProvider
}

/*
Sample response:

{\"sub\":\"837f2447-2e42-4db9-9f32-817d4866178a\",\"approved\":true,\"email_verified\":true,\"name\":\"Shoubhik Bose\",\"company\":\"red hat\",\"preferred_username\":\"shbose\",\"given_name\":\"Shoubhik\",\"family_name\":\"Bose\",\"email\":\"sbose0708@gmail.com\"}
*/

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

func NewIdentityProvider(config Configuration) *IdentityProvider {
	provider := &IdentityProvider{}
	provider.ProfileURL = config.GetUserInfoEndpoint()
	provider.ClientID = config.GetKeycloakClientID()
	provider.ClientSecret = config.GetKeycloakSecret()
	provider.Scopes = []string{"user:email"}
	provider.Endpoint = oauth2.Endpoint{AuthURL: config.GetOAuthEndpointAuth(), TokenURL: config.GetOAuthEndpointToken()}
	return provider
}

// Profile fetches a user profile from the Identity Provider
func (provider *IdentityProvider) Profile(ctx context.Context, token oauth2.Token) (*oauth.UserProfile, error) {
	body, err := provider.UserProfilePayload(ctx, token)
	if err != nil {
		return nil, err
	}
	var u oauth.UserProfile
	var idpResponse IdentityProviderResponse
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

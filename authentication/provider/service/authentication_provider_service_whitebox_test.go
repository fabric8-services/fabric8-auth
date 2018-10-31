package service

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/authentication/provider"

	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/resource"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGravatarURLGeneration(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	grURL, err := generateGravatarURL("alkazako@redhat.com")
	assert.Nil(t, err)
	assert.Equal(t, "https://www.gravatar.com/avatar/0fa6cfaa2812a200c566f671803cdf2d.jpg", grURL)
}

func TestEncodeTokenOK(t *testing.T) {
	accessToken := "accessToken%@!/\\&?"
	refreshToken := "refreshToken%@!/\\&?"
	tokenType := "tokenType%@!/\\&?"
	expiresIn := 1800
	var refreshExpiresIn float64
	refreshExpiresIn = 2.59e6

	var nbf int64
	outhToken := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
	}
	extra := map[string]interface{}{
		"expires_in":         expiresIn,
		"refresh_expires_in": refreshExpiresIn,
		"not_before_policy":  nbf,
	}
	tokenJSON, err := TokenToJSON(context.Background(), outhToken.WithExtra(extra))
	assert.Nil(t, err)
	b := []byte(tokenJSON)
	tokenData := &manager.TokenSet{}
	err = json.Unmarshal(b, tokenData)
	assert.Nil(t, err)

	assert.Equal(t, accessToken, *tokenData.AccessToken)
	assert.Equal(t, refreshToken, *tokenData.RefreshToken)
	assert.Equal(t, tokenType, *tokenData.TokenType)
	assert.Equal(t, int64(expiresIn), *tokenData.ExpiresIn)
	assert.Equal(t, int64(refreshExpiresIn), *tokenData.RefreshExpiresIn)
}

func TestFillUserDoesntOverwriteExistingImageURL(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	identity := &account.Identity{Username: "vaysa", User: account.User{FullName: "Vasya Pupkin", Company: "Red Hat", Email: "vpupkin@mail.io", ImageURL: "http://vpupkin.io/image.jpg"}}
	claims := provider.UserProfile{Username: "new username", GivenName: "new", FamilyName: "name", Company: "new company", Email: "new email"}
	fillUserFromUserInfo(claims, identity)
	assert.Equal(t, "new name", identity.User.FullName)
	assert.Equal(t, "new company", identity.User.Company)
	assert.Equal(t, "new email", identity.User.Email)
	assert.Equal(t, "new username", identity.Username)
	assert.Equal(t, "http://vpupkin.io/image.jpg", identity.User.ImageURL)
}

func TestFillUserDoesntOverwritesEmailVerified(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	identity := &account.Identity{Username: "vaysa", User: account.User{FullName: "Vasya Pupkin", Company: "Red Hat", Email: "vpupkin@mail.io", EmailVerified: false, ImageURL: "http://vpupkin.io/image.jpg"}}
	claims := provider.UserProfile{Username: "new username", GivenName: "new", FamilyName: "name", Company: "new company", Email: "new email", EmailVerified: true}
	fillUserFromUserInfo(claims, identity)
	assert.Equal(t, false, identity.User.EmailVerified)
}

func TestBuildRedirectURL(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	responseMode := "fragment"
	t.Run("with parameter and fragment", func(t *testing.T) {
		referralURL, _ := url.Parse("http://mysite?x=123")
		require.Equal(t, "http://mysite?x=123#code=thecode&state=thestate", buildRedirectURL("thecode", "thestate", referralURL, &responseMode))
	})
	t.Run("without parameter", func(t *testing.T) {
		referralURL, _ := url.Parse("http://mysite/")
		require.Equal(t, "http://mysite/#code=thecode&state=thestate", buildRedirectURL("thecode", "thestate", referralURL, &responseMode))
	})
	t.Run("with parameter, no response mode specified", func(t *testing.T) {
		referralURL, _ := url.Parse("http://mysite?x=123")
		require.Equal(t, "http://mysite?code=thecode&state=thestate&x=123", buildRedirectURL("thecode", "thestate", referralURL, nil))
	})
}

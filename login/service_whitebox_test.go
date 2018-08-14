package login

import (
	"context"
	"encoding/json"
	"testing"

	name "github.com/fabric8-services/fabric8-auth/account"
	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/token"

	_ "github.com/lib/pq"
	"github.com/satori/go.uuid"
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

func TestFillUserDoesntOverwriteExistingImageURL(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	identity := &account.Identity{Username: "vaysa", User: account.User{FullName: "Vasya Pupkin", Company: "Red Hat", Email: "vpupkin@mail.io", ImageURL: "http://vpupkin.io/image.jpg"}}
	claims := &token.TokenClaims{Username: "new username", Name: "new name", Company: "new company", Email: "new email"}
	isChanged, err := fillUser(claims, identity)
	require.Nil(t, err)
	require.True(t, isChanged)
	assert.Equal(t, "new name", identity.User.FullName)
	assert.Equal(t, "new company", identity.User.Company)
	assert.Equal(t, "new email", identity.User.Email)
	assert.Equal(t, "new username", identity.Username)
	assert.Equal(t, "http://vpupkin.io/image.jpg", identity.User.ImageURL)
}

func TestFillUserOverwritesEmailVerified(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	identity := &account.Identity{Username: "vaysa", User: account.User{FullName: "Vasya Pupkin", Company: "Red Hat", Email: "vpupkin@mail.io", EmailVerified: false, ImageURL: "http://vpupkin.io/image.jpg"}}
	claims := &token.TokenClaims{Username: "new username", Name: "new name", Company: "new company", Email: "new email", EmailVerified: true}
	isChanged, err := fillUser(claims, identity)
	require.Nil(t, err)
	require.True(t, isChanged)
	assert.Equal(t, true, identity.User.EmailVerified)
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
	tokenJson, err := TokenToJson(context.Background(), outhToken.WithExtra(extra))
	assert.Nil(t, err)
	b := []byte(tokenJson)
	tokenData := &token.TokenSet{}
	err = json.Unmarshal(b, tokenData)
	assert.Nil(t, err)

	assert.Equal(t, accessToken, *tokenData.AccessToken)
	assert.Equal(t, refreshToken, *tokenData.RefreshToken)
	assert.Equal(t, tokenType, *tokenData.TokenType)
	assert.Equal(t, int64(expiresIn), *tokenData.ExpiresIn)
	assert.Equal(t, int64(refreshExpiresIn), *tokenData.RefreshExpiresIn)
}

func TestEqualsTokenClaimsNotEqual(t *testing.T) {
	claims := token.TokenClaims{
		GivenName:  "testfirstname",
		FamilyName: "testlastname",
		Username:   "test",
		Company:    "test",
	}

	identity := account.Identity{
		Username: claims.Username + "noise",
		User: account.User{
			FullName:      name.GenerateFullName(&claims.GivenName, &claims.FamilyName),
			Email:         claims.Email + "noise",
			EmailVerified: !claims.EmailVerified,
		},
	}

	oauthServiceProvider := OAuthServiceProvider{}
	assert.Equal(t, false, oauthServiceProvider.equalsTokenClaims(context.Background(), &claims, identity))
}

func TestEqualsTokenClaimsEqual(t *testing.T) {
	claims := token.TokenClaims{
		GivenName:     "testfirstname",
		FamilyName:    "testlastname",
		Username:      "test",
		Company:       "test",
		EmailVerified: false,
		Email:         "test",
	}

	identity := account.Identity{
		Username: claims.Username,
		User: account.User{
			FullName:      name.GenerateFullName(&claims.GivenName, &claims.FamilyName),
			Email:         claims.Email,
			Company:       claims.Company,
			EmailVerified: false,
		},
	}

	oauthServiceProvider := OAuthServiceProvider{}
	assert.Equal(t, true, oauthServiceProvider.equalsTokenClaims(context.Background(), &claims, identity))
}

func TestEqualsOAuthServiceAttributes(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	oauthServiceAttributes := OAuthServiceUserProfileAttributes{
		"bio":      []string{"hello", "hi"},
		"image":    []string{},
		"approved": []string{"true"},
	}

	assert.Equal(t, true, equalsOAuthServiceAttribute(oauthServiceAttributes, "bio", "hello"))
	assert.Equal(t, false, equalsOAuthServiceAttribute(oauthServiceAttributes, "bio", "hi"))
	assert.Equal(t, false, equalsOAuthServiceAttribute(oauthServiceAttributes, "image", "no image"))
	assert.Equal(t, true, equalsOAuthServiceAttribute(oauthServiceAttributes, "approved", "true"))
}

func TestEqualsOAuthServiceUserProfileAttributes(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	service := OAuthServiceProvider{}
	username := "username"
	emailVerified := true
	firstName := "john"
	lastName := "doe"
	email := "a@a.com"

	dummyUserProfileResponse := OAuthServiceUserProfileResponse{
		Username:      &username,
		EmailVerified: &emailVerified,
		FirstName:     &firstName,
		LastName:      &lastName,
		Email:         &email,
		Attributes: &OAuthServiceUserProfileAttributes{
			BioAttributeName:      []string{"mybio"},
			ImageURLAttributeName: []string{"myurl"},
			CompanyAttributeName:  []string{"redhat"},
			ClusterAttribute:      []string{"cluster"},
		},
	}

	identity := account.Identity{
		Username: username,
		User: account.User{
			FullName:      "john doe",
			Email:         email,
			Bio:           "mybio",
			ImageURL:      "myurl",
			Company:       "redhat",
			Cluster:       "cluster",
			EmailVerified: emailVerified,
		},
	}

	service.oauthProfileService = newDummyUserProfileService(&dummyUserProfileResponse)
	isEqual, err := service.equalsOAuthServiceUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, true, isEqual)

	identity.User.Bio = ""
	isEqual, err = service.equalsOAuthServiceUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, false, isEqual)

	identity.User.EmailVerified = false
	isEqual, err = service.equalsOAuthServiceUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, false, isEqual)

	identity.User.Email = "some other unverified email"
	isEqual, err = service.equalsOAuthServiceUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, false, isEqual)

	identity.Username = "some other unverified username"
	isEqual, err = service.equalsOAuthServiceUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, false, isEqual)
}

// a mock oauth service user profile service specific to our use case.

type dummyUserProfileService struct {
	dummyGetResponse *OAuthServiceUserProfileResponse
}

func newDummyUserProfileService(dummyGetResponse *OAuthServiceUserProfileResponse) *dummyUserProfileService {
	return &dummyUserProfileService{
		dummyGetResponse: dummyGetResponse,
	}
}

func (d *dummyUserProfileService) Update(ctx context.Context, oauthServiceUserProfile *OAuthServiceUserProfile, accessToken string, oauthServiceProfileURL string) error {
	return nil
}

func (d *dummyUserProfileService) Get(ctx context.Context, accessToken string, oauthServiceProfileURL string) (*OAuthServiceUserProfileResponse, error) {
	return d.dummyGetResponse, nil
}

func (d *dummyUserProfileService) CreateOrUpdate(ctx context.Context, oauthServiceUserProfile *OAuthServiceUserRequest, accessToken string, oauthServiceProfileURL string) (*string, bool, error) {
	url := "https://someurl/pathinoauthserviceurl/" + uuid.NewV4().String()
	return &url, true, nil
}

func (d *dummyUserProfileService) SetDummyGetResponse(dummyGetResponse *OAuthServiceUserProfileResponse) {
	d.dummyGetResponse = dummyGetResponse
}

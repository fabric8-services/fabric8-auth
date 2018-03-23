package login

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
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
			FullName:      account.GenerateFullName(&claims.GivenName, &claims.FamilyName),
			Email:         claims.Email + "noise",
			EmailVerified: !claims.EmailVerified,
		},
	}

	keycloakOAuthProvider := KeycloakOAuthProvider{}
	assert.Equal(t, false, keycloakOAuthProvider.equalsTokenClaims(context.Background(), &claims, identity))
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
			FullName:      account.GenerateFullName(&claims.GivenName, &claims.FamilyName),
			Email:         claims.Email,
			Company:       claims.Company,
			EmailVerified: false,
		},
	}

	keycloakOAuthProvider := KeycloakOAuthProvider{}
	assert.Equal(t, true, keycloakOAuthProvider.equalsTokenClaims(context.Background(), &claims, identity))
}

func TestEqualsKeycloakAttributes(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	keycloakAttributes := KeycloakUserProfileAttributes{
		"bio":      []string{"hello", "hi"},
		"image":    []string{},
		"approved": []string{"true"},
	}

	assert.Equal(t, true, equalsKeycloakAttribute(keycloakAttributes, "bio", "hello"))
	assert.Equal(t, false, equalsKeycloakAttribute(keycloakAttributes, "bio", "hi"))
	assert.Equal(t, false, equalsKeycloakAttribute(keycloakAttributes, "image", "no image"))
	assert.Equal(t, true, equalsKeycloakAttribute(keycloakAttributes, "approved", "true"))
}

func TestEqualsKeycloakUserProfileAttributes(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	service := KeycloakOAuthProvider{}
	username := "username"
	emailVerified := true
	firstName := "john"
	lastName := "doe"
	email := "a@a.com"

	dummyUserProfileResponse := KeycloakUserProfileResponse{
		Username:      &username,
		EmailVerified: &emailVerified,
		FirstName:     &firstName,
		LastName:      &lastName,
		Email:         &email,
		Attributes: &KeycloakUserProfileAttributes{
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

	service.keycloakProfileService = newDummyUserProfileService(&dummyUserProfileResponse)
	isEqual, err := service.equalsKeycloakUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, true, isEqual)

	identity.User.Bio = ""
	isEqual, err = service.equalsKeycloakUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, false, isEqual)

	identity.User.EmailVerified = false
	isEqual, err = service.equalsKeycloakUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, false, isEqual)

	identity.User.Email = "some other unverified email"
	isEqual, err = service.equalsKeycloakUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, false, isEqual)

	identity.Username = "some other unverified username"
	isEqual, err = service.equalsKeycloakUserProfileAttributes(context.Background(), "doesnt matter", identity, "doesn't matter")
	require.NoError(t, err)
	assert.Equal(t, false, isEqual)
}

// a mock keycloak user profile service specific to our use case.

type dummyUserProfileService struct {
	dummyGetResponse *KeycloakUserProfileResponse
}

func newDummyUserProfileService(dummyGetResponse *KeycloakUserProfileResponse) *dummyUserProfileService {
	return &dummyUserProfileService{
		dummyGetResponse: dummyGetResponse,
	}
}

func (d *dummyUserProfileService) Update(ctx context.Context, keycloakUserProfile *KeycloakUserProfile, accessToken string, keycloakProfileURL string) error {
	return nil
}

func (d *dummyUserProfileService) Get(ctx context.Context, accessToken string, keycloakProfileURL string) (*KeycloakUserProfileResponse, error) {
	return d.dummyGetResponse, nil
}

func (d *dummyUserProfileService) CreateOrUpdate(ctx context.Context, keycloakUserProfile *KeytcloakUserRequest, accessToken string, keycloakProfileURL string) (*string, bool, error) {
	url := "https://someurl/pathinkeycloakurl/" + uuid.NewV4().String()
	return &url, true, nil
}

func (d *dummyUserProfileService) SetDummyGetResponse(dummyGetResponse *KeycloakUserProfileResponse) {
	d.dummyGetResponse = dummyGetResponse
}

package login

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/auth"
	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

var (
	oauth         *oauth2.Config
	configuration *config.ConfigurationData
	loginService  *KeycloakOAuthProvider
)

func init() {
	var err error
	configuration, err = config.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}

	oauth = &oauth2.Config{
		ClientID:     configuration.GetKeycloakClientID(),
		ClientSecret: configuration.GetKeycloakSecret(),
		Scopes:       []string{"user:email"},
		Endpoint:     oauth2.Endpoint{},
	}
}

func setup() {
	userRepository := account.NewUserRepository(nil)
	identityRepository := account.NewIdentityRepository(nil)
	loginService = &KeycloakOAuthProvider{
		Identities:   identityRepository,
		Users:        userRepository,
		TokenManager: testtoken.TokenManager,
	}
}

func tearDown() {
	loginService = nil
}

func TestGravatarURLGeneration(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	grURL, err := generateGravatarURL("alkazako@redhat.com")
	assert.Nil(t, err)
	assert.Equal(t, "https://www.gravatar.com/avatar/0fa6cfaa2812a200c566f671803cdf2d.jpg", grURL)
}

func TestEncodeTokenOK(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	referelURL, _ := url.Parse("https://example.domain.com")
	accessToken := "accessToken%@!/\\&?"
	refreshToken := "refreshToken%@!/\\&?"
	tokenType := "tokenType%@!/\\&?"
	expiresIn := 1800
	var refreshExpiresIn float64
	refreshExpiresIn = 2.59e6

	outhToken := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
	}
	extra := map[string]interface{}{
		"expires_in":         expiresIn,
		"refresh_expires_in": refreshExpiresIn,
	}
	err := encodeToken(context.Background(), referelURL, outhToken.WithExtra(extra))
	assert.Nil(t, err)
	encoded := referelURL.String()

	referelURL, _ = url.Parse(encoded)
	values := referelURL.Query()
	tJSON := values["token_json"]
	b := []byte(tJSON[0])
	tokenData := &auth.Token{}
	err = json.Unmarshal(b, tokenData)
	assert.Nil(t, err)

	assert.Equal(t, accessToken, *tokenData.AccessToken)
	assert.Equal(t, refreshToken, *tokenData.RefreshToken)
	assert.Equal(t, tokenType, *tokenData.TokenType)
	assert.Equal(t, int64(expiresIn), *tokenData.ExpiresIn)
	assert.Equal(t, int64(refreshExpiresIn), *tokenData.RefreshExpiresIn)
}

func TestInt32ToInt64OK(t *testing.T) {
	var i32 int32
	i32 = 60
	i, err := numberToInt(i32)
	assert.Nil(t, err)
	assert.Equal(t, int64(i32), i)
}

func TestInt64ToInt64OK(t *testing.T) {
	var i64 int64
	i64 = 6000000000000000000
	i, err := numberToInt(i64)
	assert.Nil(t, err)
	assert.Equal(t, i64, i)
}

func TestFloat32ToInt64OK(t *testing.T) {
	var f32 float32
	f32 = 0.1e1
	i, err := numberToInt(f32)
	assert.Nil(t, err)
	assert.Equal(t, int64(f32), i)
}

func TestFloat64ToInt64OK(t *testing.T) {
	var f64 float64
	f64 = 0.1e10
	i, err := numberToInt(f64)
	assert.Nil(t, err)
	assert.Equal(t, int64(f64), i)
}

func TestStringToInt64OK(t *testing.T) {
	str := "2590000"
	i, err := numberToInt(str)
	assert.Nil(t, err)
	assert.Equal(t, int64(2590000), i)
}

func TestApprovedUserOK(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	var attributes KeycloakUserProfileAttributes
	attributes = make(map[string][]string)
	attributes[ApprovedAttributeName] = []string{"true"}
	profile := &KeycloakUserProfileResponse{Attributes: &attributes}
	approved, err := checkApproved(context.Background(), newDummyUserProfileService(profile), "", "")
	assert.Nil(t, err)
	assert.True(t, approved)
}

func TestNotApprovedUserFails(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	approved, err := checkApproved(context.Background(), newDummyUserProfileService(&KeycloakUserProfileResponse{}), "", "")
	assert.Nil(t, err)
	assert.False(t, approved)

	var attributes KeycloakUserProfileAttributes
	attributes = make(map[string][]string)
	profile := &KeycloakUserProfileResponse{Attributes: &attributes}

	approved, err = checkApproved(context.Background(), newDummyUserProfileService(profile), "", "")
	assert.Nil(t, err)
	assert.False(t, approved)

	attributes[ApprovedAttributeName] = []string{"false"}

	approved, err = checkApproved(context.Background(), newDummyUserProfileService(profile), "", "")
	assert.Nil(t, err)
	assert.False(t, approved)

	attributes[ApprovedAttributeName] = []string{"blahblah", "anydata"}

	approved, err = checkApproved(context.Background(), newDummyUserProfileService(profile), "", "")
	assert.NotNil(t, err)
	assert.False(t, approved)
}

func TestFillUserDoesntOverwriteExistingImageURL(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)

	user := &account.User{FullName: "Vasya Pupkin", Company: "Red Hat", Email: "vpupkin@mail.io", ImageURL: "http://vpupkin.io/image.jpg"}
	identity := &account.Identity{Username: "vaysa"}
	claims := &token.TokenClaims{Username: "new username", Name: "new name", Company: "new company", Email: "new email"}
	isChanged, err := fillUser(claims, user, identity)
	require.Nil(t, err)
	require.True(t, isChanged)
	assert.Equal(t, "new name", user.FullName)
	assert.Equal(t, "new company", user.Company)
	assert.Equal(t, "new email", user.Email)
	assert.Equal(t, "new username", identity.Username)
	assert.Equal(t, "http://vpupkin.io/image.jpg", user.ImageURL)
}

type dummyUserProfileService struct {
	profile *KeycloakUserProfileResponse
}

func newDummyUserProfileService(profile *KeycloakUserProfileResponse) *dummyUserProfileService {
	return &dummyUserProfileService{profile: profile}
}

func (d *dummyUserProfileService) Update(ctx context.Context, keycloakUserProfile *KeycloakUserProfile, accessToken string, keycloakProfileURL string) error {
	return nil
}

func (d *dummyUserProfileService) Get(ctx context.Context, accessToken string, keycloakProfileURL string) (*KeycloakUserProfileResponse, error) {
	return d.profile, nil
}

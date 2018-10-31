package service_test

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/authentication/provider"
	tokenmanager "github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/resource"

	_ "github.com/lib/pq"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserProfileServiceBlackBoxTest struct {
	gormtestsupport.DBTestSuite
	clean       func()
	accessToken *string
}

func TestRunUserProfileServiceBlackBoxTest(t *testing.T) {
	suite.Run(t, &UserProfileServiceBlackBoxTest{DBTestSuite: gormtestsupport.NewDBTestSuite()})
}

// SetupSuite overrides the RemoteTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
func (s *UserProfileServiceBlackBoxTest) SetupSuite() {
	resource.Require(s.T(), resource.Remote)
	var err error

	// Get the access token ONCE which we will use for all profile related tests.
	//  - avoid repition in every test.
	token, err := s.generateAccessToken() // TODO: Use a simpler way to do this.
	assert.Nil(s.T(), err)
	s.accessToken = token

	// Get the initial profile state.
	profile, err := s.Application.UserProfileService().Get(context.Background(), *s.accessToken, s.Configuration.GetOAuthProviderEndpointUserInfo())
	require.Nil(s.T(), err)
	require.NotNil(s.T(), profile)

	initialProfileState := &provider.OAuthUserProfile{
		Attributes: profile.Attributes,
		FirstName:  profile.FirstName,
		LastName:   profile.LastName,
		Email:      profile.Email,
		Username:   profile.Username,
	}

	// Schedule it for restoring of the initial state of the keycloak user after the test
	s.clean = s.updateUserProfile(initialProfileState)
}

func (s *UserProfileServiceBlackBoxTest) TearDownTest() {
	s.clean()
}

func (s *UserProfileServiceBlackBoxTest) generateAccessToken() (*string, error) {

	client := &http.Client{Timeout: 10 * time.Second}
	tokenEndpoint := s.Configuration.GetOAuthProviderEndpointToken()

	res, err := client.PostForm(tokenEndpoint, url.Values{
		"client_id":     {s.Configuration.GetOAuthProviderClientID()},
		"client_secret": {s.Configuration.GetOAuthProviderClientSecret()},
		"username":      {"testuser"},
		"password":      {"testuser"},
		"grant_type":    {"password"},
	})
	if err != nil {
		return nil, errors.NewInternalError(context.Background(), errs.Wrap(err, "error when obtaining token"))
	}

	t, err := tokenmanager.ReadTokenSet(context.Background(), res)
	require.Nil(s.T(), err)
	return t.AccessToken, err
}

func (s *UserProfileServiceBlackBoxTest) TestKeycloakUserProfileUpdate() {

	// UPDATE the user profile

	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := "updatedEmail" + uuid.NewV4().String() + "@email.com"
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "testuserupdated"

	testKeycloakUserProfileAttributes := &provider.OAuthUserProfileAttributes{
		provider.ImageURLAttributeName: []string{testImageURL},
		provider.BioAttributeName:      []string{testBio},
		provider.URLAttributeName:      []string{testURL},
	}

	testKeycloakUserProfileData := provider.NewOAuthUserProfile(&testFirstName, &testLastName, &testEmail, testKeycloakUserProfileAttributes)
	testKeycloakUserProfileData.Username = &testUserName

	updateProfileFunc := s.updateUserProfile(testKeycloakUserProfileData)
	updateProfileFunc()

	// Do a GET on the user profile
	// Use the token to update user profile
	retrievedkeycloakUserProfileData, err := s.Application.UserProfileService().Get(context.Background(), *s.accessToken, s.Configuration.GetOAuthProviderEndpointUserInfo())
	require.Nil(s.T(), err)
	require.NotNil(s.T(), retrievedkeycloakUserProfileData)

	assert.Equal(s.T(), testFirstName, *retrievedkeycloakUserProfileData.FirstName)
	assert.Equal(s.T(), testLastName, *retrievedkeycloakUserProfileData.LastName)
	assert.Equal(s.T(), testUserName, *retrievedkeycloakUserProfileData.Username)

	// email is automatically stored in lower case
	assert.Equal(s.T(), strings.ToLower(testEmail), *retrievedkeycloakUserProfileData.Email)

	// validate Attributes
	retrievedBio := (*retrievedkeycloakUserProfileData.Attributes)[provider.BioAttributeName]
	assert.Equal(s.T(), retrievedBio[0], testBio)

}

func (s *UserProfileServiceBlackBoxTest) TestKeycloakUserProfileGet() {
	profile, err := s.Application.UserProfileService().Get(context.Background(), *s.accessToken, s.Configuration.GetOAuthProviderEndpointUserInfo())

	require.Nil(s.T(), err)
	assert.NotNil(s.T(), profile)

	keys := reflect.ValueOf(*profile.Attributes).MapKeys()
	assert.NotEqual(s.T(), len(keys), 0)
	assert.NotNil(s.T(), *profile.FirstName)
	assert.NotNil(s.T(), *profile.LastName)
	assert.NotNil(s.T(), *profile.Email)
	assert.NotNil(s.T(), *profile.Attributes)
}

func (s *UserProfileServiceBlackBoxTest) updateUserProfile(userProfile *provider.OAuthUserProfile) func() {
	return func() {
		err := s.Application.UserProfileService().Update(context.Background(), userProfile, *s.accessToken, s.Configuration.GetOAuthProviderEndpointUserInfo())
		require.Nil(s.T(), err)
	}
}

package login_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/goadesign/goa"
	_ "github.com/lib/pq"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ProfileBlackBoxTest struct {
	testsuite.RemoteTestSuite
	clean          func()
	profileService login.UserProfileService
	loginService   *login.KeycloakOAuthProvider
	accessToken    *string
	profileAPIURL  *string
}

func TestRunProfileBlackBoxTest(t *testing.T) {
	suite.Run(t, &ProfileBlackBoxTest{RemoteTestSuite: testsuite.NewRemoteTestSuite()})
}

// SetupSuite overrides the RemoteTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
func (s *ProfileBlackBoxTest) SetupSuite() {
	resource.Require(s.T(), resource.Remote)
	var err error
	s.Config, err = configuration.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}

	keycloakUserProfileService := login.NewKeycloakUserProfileClient()
	s.profileService = keycloakUserProfileService

	// Get the API endpoint - avoid repition in every test.
	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	profileAPIURL, err := s.Config.GetKeycloakAccountEndpoint(r)
	s.profileAPIURL = &profileAPIURL

	// Get the access token ONCE which we will use for all profile related tests.
	//  - avoid repition in every test.
	token, err := s.generateAccessToken() // TODO: Use a simpler way to do this.
	assert.Nil(s.T(), err)
	s.accessToken = token

	// Get the initial profile state.
	profile, err := s.profileService.Get(context.Background(), *s.accessToken, *s.profileAPIURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), profile)

	initialProfileState := &login.KeycloakUserProfile{
		Attributes: profile.Attributes,
		FirstName:  profile.FirstName,
		LastName:   profile.LastName,
		Email:      profile.Email,
		Username:   profile.Username,
	}

	// Schedule it for restoring of the initial state of the keycloak user after the test
	s.clean = s.updateUserProfile(initialProfileState)
}

func (s *ProfileBlackBoxTest) TearDownTest() {
	s.clean()
}

func (s *ProfileBlackBoxTest) generateAccessToken() (*string, error) {

	var scopes []account.Identity
	scopes = append(scopes, test.TestIdentity)
	scopes = append(scopes, test.TestObserverIdentity)

	client := &http.Client{Timeout: 10 * time.Second}
	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}
	tokenEndpoint, err := s.Config.GetKeycloakEndpointToken(r)

	res, err := client.PostForm(tokenEndpoint, url.Values{
		"client_id":     {s.Config.GetKeycloakClientID()},
		"client_secret": {s.Config.GetKeycloakSecret()},
		"username":      {s.Config.GetKeycloakTestUserName()},
		"password":      {s.Config.GetKeycloakTestUserSecret()},
		"grant_type":    {"password"},
	})
	if err != nil {
		return nil, errors.NewInternalError(context.Background(), errs.Wrap(err, "error when obtaining token"))
	}

	t, err := token.ReadTokenSet(context.Background(), res)
	require.Nil(s.T(), err)
	return t.AccessToken, err
}

func (s *ProfileBlackBoxTest) TestKeycloakUserProfileUpdate() {

	// UPDATE the user profile

	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := "updatedEmail" + uuid.NewV4().String() + "@email.com"
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "testuserupdated"

	testKeycloakUserProfileAttributes := &login.KeycloakUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testKeycloakUserProfileData := login.NewKeycloakUserProfile(&testFirstName, &testLastName, &testEmail, testKeycloakUserProfileAttributes)
	testKeycloakUserProfileData.Username = &testUserName

	updateProfileFunc := s.updateUserProfile(testKeycloakUserProfileData)
	updateProfileFunc()

	// Do a GET on the user profile
	// Use the token to update user profile
	retrievedkeycloakUserProfileData, err := s.profileService.Get(context.Background(), *s.accessToken, *s.profileAPIURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), retrievedkeycloakUserProfileData)

	assert.Equal(s.T(), testFirstName, *retrievedkeycloakUserProfileData.FirstName)
	assert.Equal(s.T(), testLastName, *retrievedkeycloakUserProfileData.LastName)
	assert.Equal(s.T(), testUserName, *retrievedkeycloakUserProfileData.Username)

	// email is automatically stored in lower case
	assert.Equal(s.T(), strings.ToLower(testEmail), *retrievedkeycloakUserProfileData.Email)

	// validate Attributes
	retrievedBio := (*retrievedkeycloakUserProfileData.Attributes)[login.BioAttributeName]
	assert.Equal(s.T(), retrievedBio[0], testBio)

}

func (s *ProfileBlackBoxTest) TestKeycloakUserProfileGet() {
	profile, err := s.profileService.Get(context.Background(), *s.accessToken, *s.profileAPIURL)

	require.Nil(s.T(), err)
	assert.NotNil(s.T(), profile)

	keys := reflect.ValueOf(*profile.Attributes).MapKeys()
	assert.NotEqual(s.T(), len(keys), 0)
	assert.NotNil(s.T(), *profile.FirstName)
	assert.NotNil(s.T(), *profile.LastName)
	assert.NotNil(s.T(), *profile.Email)
	assert.NotNil(s.T(), *profile.Attributes)
}

func (s *ProfileBlackBoxTest) updateUserProfile(userProfile *login.KeycloakUserProfile) func() {
	return func() {
		err := s.profileService.Update(context.Background(), userProfile, *s.accessToken, *s.profileAPIURL)
		require.Nil(s.T(), err)
	}
}

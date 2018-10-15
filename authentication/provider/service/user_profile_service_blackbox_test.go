package service_test

import (
	"context"
	"fmt"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/configuration"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/auth"
	"github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/login/link"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ProfileUserBlackBoxTest struct {
	testsuite.RemoteTestSuite
	profileService       login.UserProfileService
	loginService         *login.KeycloakOAuthProvider
	idpLinkService       link.KeycloakIDPService
	protectedAccessToken string
	userAPIFOrAdminURL   string
	tokenEndpoint        string
}

func TestRunProfileUserBlackBoxTest(t *testing.T) {
	suite.Run(t, &ProfileUserBlackBoxTest{RemoteTestSuite: testsuite.NewRemoteTestSuite()})
}

// SetupSuite overrides the RemoteTestSuite's function but calls it before doing anything else
// The SetupSuite method will run before the tests in the suite are run.
func (s *ProfileUserBlackBoxTest) SetupSuite() {
	s.RemoteTestSuite.SetupSuite()
	if s.Config.IsKeycloakTestsDisabled() {
		s.T().Skip("Skipping Keycloak tests")
	}
	var err error
	keycloakUserProfileService := login.NewKeycloakUserProfileClient()
	s.profileService = keycloakUserProfileService

	s.idpLinkService = link.NewKeycloakIDPServiceClient()

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	s.tokenEndpoint, err = s.Config.GetKeycloakEndpointToken(r)
	assert.Nil(s.T(), err)

	// http://sso.prod-preview.openshift.io/auth/admin/realms/fabric8/users"
	s.userAPIFOrAdminURL, err = s.Config.GetKeycloakEndpointUsers(r)
	assert.Nil(s.T(), err)

	token, err := s.generateProtectedAccessToken()
	assert.Nil(s.T(), err)
	require.NotNil(s.T(), token)
	s.protectedAccessToken = *token
}

func (s *ProfileUserBlackBoxTest) generateProtectedAccessToken() (*string, error) {
	clientID := s.Config.GetKeycloakClientID()
	clientSecret := s.Config.GetKeycloakSecret()
	token, err := auth.GetProtectedAPIToken(context.Background(), s.tokenEndpoint, clientID, clientSecret)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), token)

	return &token, err
}

/*

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

*/

func (s *ProfileUserBlackBoxTest) TestPATGenerated() {
	assert.NotEmpty(s.T(), s.protectedAccessToken)
}

func (s *ProfileUserBlackBoxTest) TestKeycloakAddUser() {
	// UPDATE the user profile

	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := "updatedEmail" + uuid.NewV4().String() + "@email.com"
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "sbosetestusercreate" + uuid.NewV4().String()
	testEnabled := true
	testEmailVerified := true

	testKeycloakUserProfileAttributes := &login.KeycloakUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testKeycloakUserData := login.KeycloakUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testKeycloakUserProfileAttributes,
	}

	userURL := s.createUser(&testKeycloakUserData)

	// TODO: Handle error, check if there was actually a URL returned.
	userURLComponents := strings.Split(*userURL, "/")
	identityID := userURLComponents[len(userURLComponents)-1]
	idpName := "rhd"
	linkRequest := link.KeycloakLinkIDPRequest{
		UserID:           &identityID,
		Username:         testKeycloakUserData.Username,
		IdentityProvider: &idpName,
	}

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	//"https://sso.prod-preview.openshift.io/auth/admin/realms/fabric8/users/" + identityID + "/federated-identity/rhd"
	linkURL, err := s.Config.GetKeycloakEndpointLinkIDP(r, identityID, idpName)
	require.Nil(s.T(), err)

	err = s.idpLinkService.Create(context.Background(), &linkRequest, s.protectedAccessToken, linkURL)
	require.Nil(s.T(), err)

	userURL = s.updateExistingUser(&testKeycloakUserData)
}

func (s *ProfileUserBlackBoxTest) TestKeycloakUpdateExistingUser() {
	// UPDATE the user profile

	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := "updatedEmail" + uuid.NewV4().String() + "@email.com"
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "sbosetestusercreate" + uuid.NewV4().String()
	testEnabled := true
	testEmailVerified := true

	testKeycloakUserProfileAttributes := &login.KeycloakUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testKeycloakUserData := login.KeycloakUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testKeycloakUserProfileAttributes,
	}

	s.createUser(&testKeycloakUserData)
	s.updateExistingUser(&testKeycloakUserData)

}

func (s *ProfileUserBlackBoxTest) TestCreateKeycloakUserWithDefaults() {

	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := "updatedEmail" + uuid.NewV4().String() + "@email.com"
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "sev1testsbosetestusercreate" + uuid.NewV4().String()

	testKeycloakUserProfileAttributes := &login.KeycloakUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testKeycloakUserData := login.KeycloakUserRequest{
		Username:   &testUserName,
		FirstName:  &testFirstName,
		LastName:   &testLastName,
		Email:      &testEmail,
		Attributes: testKeycloakUserProfileAttributes,
	}

	s.createUser(&testKeycloakUserData)
	// verified on keycloak
}

func (s *ProfileUserBlackBoxTest) TestKeycloakCreateNewUserWithExistingEmail() {
	// UPDATE the user profile

	emailToBeUpdatedFor409 := "unitestupdatedmail" + uuid.NewV4().String() + "@email.com"
	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := emailToBeUpdatedFor409
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "unittestsbosetestusercreate" + uuid.NewV4().String()
	testEnabled := true
	testEmailVerified := true

	testKeycloakUserProfileAttributes := &login.KeycloakUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testKeycloakUserData := login.KeycloakUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testKeycloakUserProfileAttributes,
	}

	s.createUser(&testKeycloakUserData)

	// Create second user

	*(testKeycloakUserData).Email = "unittestupdatedemail" + uuid.NewV4().String() + "@email.com"
	*(testKeycloakUserData).Username = "unitestupdatedusername" + uuid.NewV4().String() + "@email.com"

	s.createUser(&testKeycloakUserData)

	// Try updating second user with first user's email.
	*(testKeycloakUserData).Email = emailToBeUpdatedFor409

	// should fail with a 409
	s.updateExistingUser409(&testKeycloakUserData)

}

func (s *ProfileUserBlackBoxTest) createUser(userProfile *login.KeycloakUserRequest) *string {
	url, created, err := s.profileService.CreateOrUpdate(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), url)
	require.True(s.T(), created)
	return url
}

func (s *ProfileUserBlackBoxTest) updateExistingUser(userProfile *login.KeycloakUserRequest) *string {
	url, created, err := s.profileService.CreateOrUpdate(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), url)
	require.False(s.T(), created)
	return url
}

func (s *ProfileUserBlackBoxTest) updateExistingUser409(userProfile *login.KeycloakUserRequest) *string {
	url, created, err := s.profileService.CreateOrUpdate(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.VersionConflictError{}, err)
	require.Nil(s.T(), url)
	require.False(s.T(), created)
	return url
}

func (s *ProfileBlackBoxTest) generateAccessToken() (*string, error) {

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

package login_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

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

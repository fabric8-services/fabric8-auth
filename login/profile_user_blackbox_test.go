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
	loginService         *login.OAuthServiceProvider
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
	if s.Config.IsOAuthServiceTestsDisabled() {
		s.T().Skip("Skipping OAuth Service tests")
	}
	var err error
	oauthUserProfileService := login.NewOAuthServiceUserProfileClient()
	s.profileService = oauthUserProfileService

	s.idpLinkService = link.NewKeycloakIDPServiceClient()

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	s.tokenEndpoint, err = s.Config.GetOAuthServiceEndpointToken(r)
	assert.Nil(s.T(), err)

	// http://sso.prod-preview.openshift.io/auth/admin/realms/fabric8/users"
	s.userAPIFOrAdminURL, err = s.Config.GetOAuthServiceEndpointUsers(r)
	assert.Nil(s.T(), err)

	token, err := s.generateProtectedAccessToken()
	assert.Nil(s.T(), err)
	require.NotNil(s.T(), token)
	s.protectedAccessToken = *token
}

func (s *ProfileUserBlackBoxTest) generateProtectedAccessToken() (*string, error) {
	clientID := s.Config.GetOAuthServiceClientID()
	clientSecret := s.Config.GetOAuthServiceSecret()
	token, err := auth.GetProtectedAPIToken(context.Background(), s.tokenEndpoint, clientID, clientSecret)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), token)

	return &token, err
}

func (s *ProfileUserBlackBoxTest) TestPATGenerated() {
	assert.NotEmpty(s.T(), s.protectedAccessToken)
}

func (s *ProfileUserBlackBoxTest) TestOAuthServiceAddUser() {
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

	testOAuthServiceUserProfileAttributes := &login.OAuthServiceUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testOAuthServiceUserData := login.OAuthServiceUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testOAuthServiceUserProfileAttributes,
	}

	userURL := s.createUser(&testOAuthServiceUserData)

	// TODO: Handle error, check if there was actually a URL returned.
	userURLComponents := strings.Split(*userURL, "/")
	identityID := userURLComponents[len(userURLComponents)-1]
	idpName := "rhd"
	linkRequest := link.KeycloakLinkIDPRequest{
		UserID:           &identityID,
		Username:         testOAuthServiceUserData.Username,
		IdentityProvider: &idpName,
	}

	r := &goa.RequestData{
		Request: &http.Request{Host: "api.example.org"},
	}

	//"https://sso.prod-preview.openshift.io/auth/admin/realms/fabric8/users/" + identityID + "/federated-identity/rhd"
	linkURL, err := s.Config.GetOAuthServiceEndpointLinkIDP(r, identityID, idpName)
	require.Nil(s.T(), err)

	err = s.idpLinkService.Create(context.Background(), &linkRequest, s.protectedAccessToken, linkURL)
	require.Nil(s.T(), err)

	s.updateExistingUser(&testOAuthServiceUserData)
}

func (s *ProfileUserBlackBoxTest) TestOAuthServiceUpdateExistingUser() {
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

	testOAuthServiceUserProfileAttributes := &login.OAuthServiceUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testOAuthServiceUserData := login.OAuthServiceUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testOAuthServiceUserProfileAttributes,
	}

	s.createUser(&testOAuthServiceUserData)
	s.updateExistingUser(&testOAuthServiceUserData)

}

func (s *ProfileUserBlackBoxTest) TestCreateOAuthServiceUserWithDefaults() {

	testFirstName := "updatedFirstNameAgainNew" + uuid.NewV4().String()
	testLastName := "updatedLastNameNew" + uuid.NewV4().String()
	testEmail := "updatedEmail" + uuid.NewV4().String() + "@email.com"
	testBio := "updatedBioNew" + uuid.NewV4().String()
	testURL := "updatedURLNew" + uuid.NewV4().String()
	testImageURL := "updatedBio" + uuid.NewV4().String()
	testUserName := "sev1testsbosetestusercreate" + uuid.NewV4().String()

	testOAuthServiceUserProfileAttributes := &login.OAuthServiceUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testOAuthServiceUserData := login.OAuthServiceUserRequest{
		Username:   &testUserName,
		FirstName:  &testFirstName,
		LastName:   &testLastName,
		Email:      &testEmail,
		Attributes: testOAuthServiceUserProfileAttributes,
	}

	s.createUser(&testOAuthServiceUserData)
	// verified on OAuth Service
}

func (s *ProfileUserBlackBoxTest) TestOAuthServiceCreateNewUserWithExistingEmail() {
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

	testOAuthServiceUserProfileAttributes := &login.OAuthServiceUserProfileAttributes{
		login.ImageURLAttributeName: []string{testImageURL},
		login.BioAttributeName:      []string{testBio},
		login.URLAttributeName:      []string{testURL},
	}

	testOAuthServiceUserData := login.OAuthServiceUserRequest{
		Username:      &testUserName,
		Enabled:       &testEnabled,
		EmailVerified: &testEmailVerified,
		FirstName:     &testFirstName,
		LastName:      &testLastName,
		Email:         &testEmail,
		Attributes:    testOAuthServiceUserProfileAttributes,
	}

	s.createUser(&testOAuthServiceUserData)

	// Create second user

	*(testOAuthServiceUserData).Email = "unittestupdatedemail" + uuid.NewV4().String() + "@email.com"
	*(testOAuthServiceUserData).Username = "unitestupdatedusername" + uuid.NewV4().String() + "@email.com"

	s.createUser(&testOAuthServiceUserData)

	// Try updating second user with first user's email.
	*(testOAuthServiceUserData).Email = emailToBeUpdatedFor409

	// should fail with a 409
	s.updateExistingUser409(&testOAuthServiceUserData)

}

func (s *ProfileUserBlackBoxTest) createUser(userProfile *login.OAuthServiceUserRequest) *string {
	url, created, err := s.profileService.CreateOrUpdate(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), url)
	require.True(s.T(), created)
	return url
}

func (s *ProfileUserBlackBoxTest) updateExistingUser(userProfile *login.OAuthServiceUserRequest) *string {
	url, created, err := s.profileService.CreateOrUpdate(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), url)
	require.False(s.T(), created)
	return url
}

func (s *ProfileUserBlackBoxTest) updateExistingUser409(userProfile *login.OAuthServiceUserRequest) *string {
	url, created, err := s.profileService.CreateOrUpdate(context.Background(), userProfile, s.protectedAccessToken, s.userAPIFOrAdminURL)
	require.Error(s.T(), err)
	require.IsType(s.T(), errors.VersionConflictError{}, err)
	require.Nil(s.T(), url)
	require.False(s.T(), created)
	return url
}

package integration

import (
	"context"
	"log"
	"net/http"
	"testing"
	"time"

	account "github.com/fabric8-services/fabric8-auth/authentication/account/repository"
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	"github.com/fabric8-services/fabric8-auth/client"
	"github.com/fabric8-services/fabric8-auth/goasupport"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	uuid "github.com/satori/go.uuid"

	goaclient "github.com/goadesign/goa/client"
	jwtgoa "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserDeactivationSuite struct {
	BaseSuite

	identity         *account.Identity
	notificationDone chan string
	deactivateDone   chan string
}

func TestUserDeactivation(t *testing.T) {
	suite.Run(t, &UserDeactivationSuite{})
}

func (s *UserDeactivationSuite) SetupTest() {
	s.notificationDone = make(chan string)
	s.deactivateDone = make(chan string)
	s.BaseSuite.SetupTest(s.notificationDone, s.deactivateDone)
}

func (s *UserDeactivationSuite) TearDownTest() {
	// explicitely clean tokens created by the standalone `auth` service
	log.Printf("deleting tokens owned by %s\n", s.identity.ID)
	if s.identity != nil {
		tokens, err := s.Application.TokenRepository().ListForIdentity(context.Background(), s.identity.ID)
		require.NoError(s.T(), err)
		for _, t := range tokens {
			err := s.DB.Table(t.TableName()).Where("token_id = ?", t.TokenID).Delete("").Error // need to do a hard delete
			require.NoError(s.T(), err)
		}
	}
	// perform standard tear down
	s.BaseSuite.TearDownTest()
}

// notification, still inactive, deactivate
func (s *UserDeactivationSuite) TestWithNoUserActivity() {
	// expectations
	expectedNotificationCalls := 1
	expectedDeactivationCalls := 1
	// test data
	s.identity = s.createUser()
	// use-case workflow
	timeout := time.NewTimer(40 * time.Second)
	notificationCalls := 0
	deactivateCalls := 0
loop:
	for {
		select {
		case identityID := <-s.notificationDone:
			log.Printf("[Test runner] user with ID '%s' was notified\n", identityID)
			notificationCalls++
			require.True(s.T(), (notificationCalls <= expectedNotificationCalls),
				"Notification calls exceeds, expected:%d, got:%d", expectedNotificationCalls, notificationCalls)
			s.updateNotificationTime(identityID, ago7days)
		case userID := <-s.deactivateDone:
			log.Println("[Test runner] deactivation call back")
			deactivateCalls++
			require.True(s.T(), (deactivateCalls <= expectedDeactivationCalls),
				"Deactivation calls exceeds, expected:%d, got:%d", expectedDeactivationCalls, deactivateCalls)
			s.verifyDeactivate(userID)
			break loop // quick exit
		case <-timeout.C:
			log.Println("[Test runner] timeout!")
			break loop // timeout exit
		}
	}
	// verifications
	assert.Equal(s.T(), expectedNotificationCalls, notificationCalls, "Unexpected number of notification calls")
	assert.Equal(s.T(), expectedDeactivationCalls, deactivateCalls, "Unexpected number of deactivation calls")
}

// notification, new activity, deactivation doesn't happen, no activity again, another notification, no activity this time, deactivation
func (s *UserDeactivationSuite) TestWithUserActivity() {
	// expectations
	expectedNotificationCalls := 2
	expectedDeactivationCalls := 1
	// test data
	s.identity = s.createUser()
	// use-case workflow
	timeout := time.NewTimer(60 * time.Second)
	notificationCalls := 0
	deactivateCalls := 0
loop:
	for {
		select {
		case identityID := <-s.notificationDone:
			log.Println("[Test runner] received notification call back")
			notificationCalls++
			require.True(s.T(), (notificationCalls <= expectedNotificationCalls),
				"Notification calls exceeds, expected:%d, got:%d", expectedNotificationCalls, notificationCalls)
			if notificationCalls == 1 {
				s.triggerActivity(s.identity)
			} else {
				s.updateNotificationTime(identityID, ago7days)
			}
		case userID := <-s.deactivateDone:
			log.Println("[Test runner] received deactivation call back")
			deactivateCalls++
			require.True(s.T(), (deactivateCalls <= expectedDeactivationCalls),
				"Deactivation calls exceeds, expected:%d, got:%d", expectedDeactivationCalls, deactivateCalls)
			s.verifyDeactivate(userID)
			break loop // quick exit
		case <-timeout.C:
			log.Println("[Test runner] timeout!")
			break loop // timeout exit
		}
	}
	// verifications
	assert.Equal(s.T(), expectedNotificationCalls, notificationCalls, "Notification calls not equal, expected:%d, got:%d", expectedNotificationCalls, notificationCalls)
	assert.Equal(s.T(), expectedDeactivationCalls, deactivateCalls, "Deactivation calls not equal, expected:%d, got:%d", expectedDeactivationCalls, deactivateCalls)
}

func (s *UserDeactivationSuite) createUser() *account.Identity {
	ctx, _, _ := testtoken.ContextWithTokenAndRequestID(s.T())
	userToDeactivate := s.Graph.CreateUser()
	userToDeactivate.User().Cluster = "starter-us-east-2"
	err := s.Application.Users().Save(ctx, userToDeactivate.User())
	require.NoError(s.T(), err)
	s.updateLastActive(userToDeactivate.Identity(), ago40days)
	return userToDeactivate.Identity()
}

func (s *UserDeactivationSuite) triggerActivity(identity *account.Identity) {
	c := client.New(goaclient.HTTPClientDoer(http.DefaultClient))
	c.Host = "localhost:8089"
	c.Scheme = "http"
	ctx := testtoken.ContextWithRequest(context.Background())

	accessToken := s.Graph.CreateToken(identity, token.TOKEN_TYPE_ACCESS).TokenString()
	refreshToken := s.Graph.CreateToken(identity, token.TOKEN_TYPE_REFRESH).TokenString()
	extracted, err := testtoken.TokenManager.Parse(context.Background(), accessToken)
	require.NoError(s.T(), err)
	ctx = jwtgoa.WithJWT(ctx, extracted)
	c.SetJWTSigner(goasupport.NewForwardSigner(ctx))
	resp, err := c.ExchangeToken(ctx, client.ExchangeTokenPath(), &client.TokenExchange{
		GrantType:    "refresh_token",
		ClientID:     s.Configuration.GetPublicOAuthClientID(),
		RefreshToken: &refreshToken,
	}, "")
	require.NoError(s.T(), err)
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	// now, check the last_active value for the user, verifies that it's close to now and move it back in the past again
	identity, err = s.Application.Identities().Load(context.Background(), identity.ID)
	require.NoError(s.T(), err)
	require.True(s.T(), identity.LastActive.After(time.Now().Add(-1*time.Minute)))
	s.updateLastActive(identity, ago40days)
	log.Println("[Test runner] identity's last active timestamp updated")
}

func (s *UserDeactivationSuite) updateLastActive(identity *account.Identity, when time.Time) {
	identity.LastActive = &when
	err := s.Application.Identities().Save(context.Background(), identity)
	require.NoError(s.T(), err)
}

type forwardSigner struct {
	token string
}

// Sign set the Auth header
func (f forwardSigner) Sign(request *http.Request) error {
	request.Header.Set("Authorization", "Bearer "+f.token)
	return nil
}

func (s *UserDeactivationSuite) updateNotificationTime(identityID string, updatedTime time.Time) {
	log.Printf("[Test runner] updating notification timestamp for user '%s'\n", identityID)
	if identityID == "" {
		s.T().Fail()
		return
	}
	// load
	id, err := uuid.FromString(identityID)
	require.NoError(s.T(), err)
	ctx := context.Background()

	// change notification time async
	attempt := 5
	for i := 1; i <= attempt; i++ {
		identity, err := s.Application.Identities().Load(ctx, id)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), identity)
		if identity.DeactivationNotification != nil {
			log.Printf("[Test runner] user's deactivation notification timestamp will be reset to %v", updatedTime.Format("2006-01-02 15:04:05"))
			identity.DeactivationNotification = &updatedTime
			scheduleDeactivation := updatedTime.Add(7 * 24 * time.Hour)
			identity.DeactivationScheduled = &scheduleDeactivation
			err = s.Application.Identities().Save(ctx, identity)
			require.NoError(s.T(), err)
			return
		}
		time.Sleep(time.Second)
	}
	identity, err := s.Application.Identities().Load(ctx, id)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), identity)
	require.NotNil(s.T(), identity.DeactivationNotification,
		"DeactivationNotification is not set after %d seconds from notification call, identity:%v", attempt, identity)
	log.Printf("[Test runner] updated notification timestamp for user '%s'\n", identityID)

}

func (s *UserDeactivationSuite) verifyDeactivate(userID string) {
	require.NotEmpty(s.T(), userID, "User deactivation can't be verified as UserID is blank")
	id, err := uuid.FromString(userID)
	require.NoError(s.T(), err)
	user, err := s.Application.Users().Load(context.Background(), id)
	assert.Error(s.T(), err) // not found as users.delete_at is set
	assert.Nil(s.T(), user)
	log.Printf("[Test runner] deactivation call verified successfully")
}

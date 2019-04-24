package integration

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	uuid "github.com/satori/go.uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type UserDeactivationSuite struct {
	BaseSuite

	NotificationDone chan string
	DeactivateDone   chan string
}

func TestUserDeactivation(t *testing.T) {
	suite.Run(t, &UserDeactivationSuite{})
}

func (s *UserDeactivationSuite) SetupTest() {
	s.NotificationDone = make(chan string)
	s.DeactivateDone = make(chan string)
	s.BaseSuite.SetupTest(s.NotificationDone, s.DeactivateDone)
}

// notification, still inactive, deactivate
func (s *UserDeactivationSuite) TestWithNoUserActivity() {
	os.Setenv("AUTH_CONFIG_FILE_PATH", "e2e_test_config.yml")

	t := s.T()
	wantNotificatinCalls := 1
	wantDeactivateCalls := 1

	// start auth_service
	cmd, display := s.authCmd()
	defer display(t)
	err := cmd.Start()
	assert.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		log.Println("Auth service stopped")
	}()
	log.Println("Auth service started")

	// test data
	s.createUser()

	// wait and varify
	timeout := time.NewTimer(40 * time.Second)
	runLoop := true
	notificatinCalls := 0
	deactivateCalls := 0
	for runLoop {
		select {
		case identityID := <-s.NotificationDone:
			log.Println("Got notification call back")
			notificatinCalls++
			assert.True(t, (notificatinCalls <= wantNotificatinCalls),
				"Notification calls exceeds, want:%d, got:%d", wantNotificatinCalls, notificatinCalls)
			s.UpdateNotificationTime(identityID, &ago7days)
		case userID := <-s.DeactivateDone:
			log.Println("Got deactivate call back")
			deactivateCalls++
			assert.True(t, (deactivateCalls <= wantDeactivateCalls),
				"Deactivation calls exceeds, want:%d, got:%d", wantDeactivateCalls, deactivateCalls)
			s.VarifyDeactivate(userID)
		case <-timeout.C:
			log.Println("Test waiting time is over")
			runLoop = false
		}
	}

	assert.Equal(t, wantNotificatinCalls, notificatinCalls, "Notification calls not equal, want:%d, got:%d", wantNotificatinCalls, notificatinCalls)
	assert.Equal(t, wantDeactivateCalls, deactivateCalls, "Deactivation calls not equal, want:%d, got:%d", wantDeactivateCalls, deactivateCalls)
}

// notification, new activity, deactivation doesn't happen, no activity again, another notification, no activity this time, deactivation
func (s *UserDeactivationSuite) TestWithUserActivity() {
	os.Setenv("AUTH_CONFIG_FILE_PATH", "e2e_test_config.yml")

	t := s.T()
	wantNotificatinCalls := 2
	wantDeactivateCalls := 1

	// start auth_service
	cmd, display := s.authCmd()
	defer display(t)
	err := cmd.Start()
	assert.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		log.Println("Auth service stopped")
	}()
	log.Println("Auth service started")

	// test data
	s.createUser()

	// wait and varify
	timeout := time.NewTimer(60 * time.Second)
	runLoop := true
	notificatinCalls := 0
	deactivateCalls := 0
	for runLoop {
		select {
		case identityID := <-s.NotificationDone:
			log.Println("Got notification call back")
			notificatinCalls++
			assert.True(t, (notificatinCalls <= wantNotificatinCalls),
				"Notification calls exceeds, want:%d, got:%d", wantNotificatinCalls, notificatinCalls)
			if notificatinCalls == 1 {
				s.UpdateNotificationTime(identityID, nil)
			} else {
				s.UpdateNotificationTime(identityID, &ago7days)
			}
		case userID := <-s.DeactivateDone:
			log.Println("Got deactivate call back")
			deactivateCalls++
			assert.True(t, (deactivateCalls <= wantDeactivateCalls),
				"Deactivation calls exceeds, want:%d, got:%d", wantDeactivateCalls, deactivateCalls)
			s.VarifyDeactivate(userID)
		case <-timeout.C:
			log.Println("Test waiting time is over")
			runLoop = false
		}
	}

	assert.Equal(t, wantNotificatinCalls, notificatinCalls, "Notification calls not equal, want:%d, got:%d", wantNotificatinCalls, notificatinCalls)
	assert.Equal(t, wantDeactivateCalls, deactivateCalls, "Deactivation calls not equal, want:%d, got:%d", wantDeactivateCalls, deactivateCalls)
}

func (s *UserDeactivationSuite) createUser() {
	ctx, _, _ := testtoken.ContextWithTokenAndRequestID(s.T())
	userToDeactivate := s.Graph.CreateUser()
	userToDeactivate.User().Cluster = "starter-us-east-2"
	err := s.Application.Users().Save(ctx, userToDeactivate.User())
	require.NoError(s.T(), err)
	identityToDeactivate := *userToDeactivate.Identity()
	identityToDeactivate.LastActive = &ago40days
	// identityToDeactivate.DeactivationNotification = &ago30days
	err = s.Application.Identities().Save(ctx, &identityToDeactivate)
	require.NoError(s.T(), err)
}

func (s *UserDeactivationSuite) UpdateNotificationTime(identityID string, updatedTime *time.Time) {
	t := s.T()
	if identityID == "" {
		t.Fail()
		return
	}

	// load
	id, err := uuid.FromString(identityID)
	require.NoError(t, err)
	ctx := context.Background()
	identity, err := s.Application.Identities().Load(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, identity)

	// change notificatin time async
	attempt := 5
	for i := 1; i <= attempt; i++ {
		identity, err := s.Application.Identities().Load(ctx, id)
		require.NoError(t, err)
		require.NotNil(t, identity)
		if identity.DeactivationNotification != nil {
			log.Printf("DeactivationNotification will be reset with %v", updatedTime)
			identity.DeactivationNotification = updatedTime
			err = s.Application.Identities().Save(ctx, identity)
			require.NoError(t, err)
			return
		} else {
			time.Sleep(time.Second)
		}
	}
	identity, err = s.Application.Identities().Load(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.NotNil(t, identity.DeactivationNotification,
		"DeactivationNotification is not set after %d seconds from notification call, identity:%v", attempt, identity)
}

func (s *UserDeactivationSuite) VerifyDeactivate(userID string) {
	t := s.T()
	require.NotNil(t, userID, "User deactivation can't be varified as UserID is nil")

	id, err := uuid.FromString(userID)
	require.NoError(t, err)
	user, err := s.Application.Users().Load(context.Background(), id)
	assert.Error(t, err) // not found as users.delete_at is set
	assert.Nil(t, user)
	log.Printf("Deactivate call varified successfully")
}

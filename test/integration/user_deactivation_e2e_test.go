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

func (s *UserDeactivationSuite) Test1() {
	t := s.T()
	os.Setenv("AUTH_CONFIG_FILE_PATH", "e2e_test_config.yml")

	// start auth_service
	cmd, display := s.authCmd()
	defer display(t)
	err := cmd.Start()
	assert.NoError(t, err)
	defer cmd.Process.Kill()

	// test data
	s.createUser()

	// wait and varify
	timeout := time.NewTimer(30 * time.Second)
	runLoop := true
	notificatinCalls := 0
	deactivateCalls := 0
	for runLoop {
		select {
		case identityID := <-s.NotificationDone:
			log.Println("Got notification call back")
			s.UpdateNotificationTime(identityID)
			notificatinCalls++
		case userID := <-s.DeactivateDone:
			log.Println("Got deactivate call back")
			s.VarifyDeactivate(userID)
			deactivateCalls++
		case <-timeout.C:
			log.Println("Timed out")
			runLoop = false
		}
	}

	wantNotificatinCalls := 1
	wantDeactivateCalls := 1
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

func (s *UserDeactivationSuite) UpdateNotificationTime(identityID string) {
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

	// change notificatin time
	identity.DeactivationNotification = &ago7days
	err = s.Application.Identities().Save(ctx, identity)
	require.NoError(t, err)
}

func (s *UserDeactivationSuite) VarifyDeactivate(userID string) {
	t := s.T()
	require.NotNil(t, userID, "User deactivation can't be varified as UserID is nil")

	id, err := uuid.FromString(userID)
	require.NoError(t, err)
	user, err := s.Application.Users().Load(context.Background(), id)
	assert.Error(t, err) // not found as users.delete_at is set
	assert.Nil(t, user)
}

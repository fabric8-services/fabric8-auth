package notification_test

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/notification"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestNotification(t *testing.T) {
	suite.Run(t, &TestNotificationSuite{})
}

type TestNotificationSuite struct {
	testsuite.UnitTestSuite
}

func (s *TestNotificationSuite) TestNewUserEmailUpdatedOK() {
	userID := uuid.NewV4().String()
	custom := make(map[string]interface{})
	custom["key"] = "value"

	msg := notification.NewUserEmailUpdated(userID, custom)
	assert.Equal(s.T(), "user.email.update", msg.MessageType)
	assert.Equal(s.T(), userID, msg.TargetID)
	assert.Equal(s.T(), &userID, msg.UserID)
	assert.Equal(s.T(), custom, msg.Custom)
}

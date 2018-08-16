package service

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/configuration"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/notification"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testconfig "github.com/fabric8-services/fabric8-auth/test/configuration"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/test/token"
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"
	tokenutil "github.com/fabric8-services/fabric8-auth/token"

	"github.com/fabric8-services/fabric8-auth/test/recorder"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"net/http"
)

func TestNotification(t *testing.T) {
	suite.Run(t, &TestNotificationSuite{})
}

type TestNotificationSuite struct {
	testsuite.UnitTestSuite
	ns                 *notificationServiceImpl
	doer               *testsupport.DummyHttpDoer
	notificationConfig *notificationURLConfig
	msg                notification.Message
}

func (s *TestNotificationSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	s.notificationConfig = &notificationURLConfig{ConfigurationData: *s.Config, notificationURL: "https://notification"}
	s.ns = NewNotificationService(nil, s.notificationConfig).(*notificationServiceImpl)

	// create a message
	customAttributes := make(map[string]interface{})
	customAttributes["temaName"] = "notification"
	customAttributes["inviter"] = "Dipak Pawar"
	customAttributes["spaceName"] = "notification testing"
	customAttributes["acceptURL"] = "localhost/accept"

	targetId := "8bccc228-bba7-43ad-b077-15fbb9148f7f"

	msg := notification.Message{
		UserID:      nil,
		Custom:      customAttributes,
		TargetID:    targetId,
		MessageType: "invitation.team.noorg",
	}

	s.msg = msg
}

func (s *TestNotificationSuite) TestCreateClientWithServiceAccountToken() {
	// create a context
	ctx := tokentestsupport.ContextWithTokenManager()
	manager, err := tokenutil.ReadManagerFromContext(ctx)
	require.Nil(s.T(), err)

	// extract the token
	saToken := (*manager).AuthServiceAccountToken()

	// create the client
	cl, err := s.ns.createClientWithContextSigner(ctx)
	require.NoError(s.T(), err)

	// create a request
	req, err := http.NewRequest("GET", "http://example.com", nil)

	// sign the request with that client
	cl.JWTSigner.Sign(req)

	authHeader := req.Header.Get("Authorization")
	require.NotEmpty(s.T(), authHeader)
	require.Equal(s.T(), "Bearer "+saToken, authHeader)
}

func (s *TestNotificationSuite) TestSend() {
	ctx, _, reqID := token.ContextWithTokenAndRequestID(s.T())

	manager, err := tokenutil.ReadManagerFromContext(ctx)
	require.Nil(s.T(), err)

	// extract the token
	saToken := (*manager).AuthServiceAccountToken()

	msg := s.msg
	messageID := new(uuid.UUID)

	r, err := recorder.New("../../test/data/notification/notification_sent.ok", recorder.WithMatcher(recorder.NotifyRequestHeaderPayloadMatcher(messageID, reqID, saToken)))
	require.NoError(s.T(), err)
	defer r.Stop()

	// create client
	cl, err := s.ns.createClientWithContextSigner(ctx, testconfig.WithRoundTripper(r.Transport))
	require.NoError(s.T(), err)

	s.T().Run("should send message", func(t *testing.T) {
		//given
		msgID, e := uuid.FromString("40bbdd3d-8b5d-4fd6-ac90-7236b669af04")
		assert.NoError(s.T(), e)

		*messageID = msgID
		msg.MessageID = msgID

		//when
		err := s.ns.send(ctx, cl, msg)

		//then
		require.NoError(s.T(), err)
	})

	s.T().Run("should fail to send message if client returned an error", func(t *testing.T) {
		//given
		msgID, e := uuid.FromString("40bbdd3d-8b5d-4fd6-ac90-7236b669af06")
		assert.NoError(s.T(), e)

		*messageID = msgID
		msg.MessageID = msgID

		//when
		err = s.ns.send(ctx, cl, msg)

		//then
		require.Error(s.T(), err)
		assert.Equal(s.T(), "unexpected response code: 400 Bad Request; response body: ", err.Error())
	})

	s.T().Run("should fail to send message if client returned an unexpected status", func(t *testing.T) {
		//given
		msgID, e := uuid.FromString("40bbdd3d-8b5d-4fd6-ac90-7236b669af05")
		assert.NoError(s.T(), e)

		*messageID = msgID
		msg.MessageID = msgID

		//when
		err = s.ns.send(ctx, cl, msg)

		//then
		require.Error(s.T(), err)
		testsupport.AssertError(s.T(), err, autherrors.InternalError{}, "unexpected response code: 500 Internal Server Error; response body: ")
	})
}

func (s *TestNotificationSuite) TestSendAsync() {
	// given
	ctx, _, _ := token.ContextWithTokenAndRequestID(s.T())
	config := &notificationURLConfig{ConfigurationData: *s.Config, notificationURL: "::::"}
	ns := NewNotificationService(nil, config).(*notificationServiceImpl)
	msg := s.msg
	messageID := new(uuid.UUID)

	r, err := recorder.New("../../test/data/notification/notification_sent.ok", recorder.WithNotifyRequestPayloadMatcher(messageID))
	require.NoError(s.T(), err)
	defer r.Stop()

	s.T().Run("should fail to send message for invalid notification url", func(t *testing.T) {
		//when
		done, errs, err := ns.SendAsync(ctx, msg)

		//then
		assert.Error(s.T(), err)
		assert.Nil(s.T(), done)
		assert.Nil(s.T(), errs)
	})

	s.T().Run("should fail to send messages for invalid notification url", func(t *testing.T) {
		//when
		done, errs, err := ns.SendMessagesAsync(ctx, []notification.Message{msg})

		//then
		assert.Error(s.T(), err)
		assert.Nil(s.T(), done)
		assert.Nil(s.T(), errs)
	})

	s.T().Run("should send messages async", func(t *testing.T) {
		//given
		ns.config = s.notificationConfig
		msgID, e := uuid.FromString("40bbdd3d-8b5d-4fd6-ac90-7236b669af04")
		assert.NoError(s.T(), e)

		*messageID = msgID
		msg.MessageID = msgID

		//when
		done, errs, err := ns.SendMessagesAsync(ctx, []notification.Message{msg}, testconfig.WithRoundTripper(r.Transport))
		<-done

		//then
		assert.NoError(s.T(), <-errs)
		assert.NoError(s.T(), err)
	})

	s.T().Run("should send message async", func(t *testing.T) {
		//given
		ns.config = s.notificationConfig
		msgID, e := uuid.FromString("40bbdd3d-8b5d-4fd6-ac90-7236b669af04")
		assert.NoError(s.T(), e)

		*messageID = msgID
		msg.MessageID = msgID

		//when
		done, errs, err := ns.SendAsync(ctx, msg, testconfig.WithRoundTripper(r.Transport))
		<-done

		//then
		assert.NoError(s.T(), <-errs)
		assert.NoError(s.T(), err)
	})
}

type notificationURLConfig struct {
	configuration.ConfigurationData
	notificationURL string
}

func (c *notificationURLConfig) GetNotificationServiceURL() string {
	return c.notificationURL
}

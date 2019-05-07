package service

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/configuration"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/rest"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"

	"net/http"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
)

func TestNotification(t *testing.T) {
	suite.Run(t, &TestNotificationSuite{})
}

type TestNotificationSuite struct {
	testsuite.UnitTestSuite
	ns                 *notificationServiceImpl
	notificationConfig *notificationURLConfig
}

func (s *TestNotificationSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	s.notificationConfig = &notificationURLConfig{
		ConfigurationData: s.Config,
		notificationURL:   "https://notification",
	}
	s.ns = NewNotificationService(nil, s.notificationConfig).(*notificationServiceImpl)
}

func (s *TestNotificationSuite) TestCreateClientWithServiceAccountToken() {
	// create a context
	ctx := tokentestsupport.ContextWithTokenManager()
	tokenManager, err := manager.ReadTokenManagerFromContext(ctx)
	require.Nil(s.T(), err)

	// extract the token
	saToken := tokenManager.AuthServiceAccountToken()

	// create the client
	cl, err := s.ns.createClientWithContextSigner(ctx)
	require.NoError(s.T(), err)

	// create a request
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// sign the request with that client
	cl.JWTSigner.Sign(req)

	authHeader := req.Header.Get("Authorization")
	require.NotEmpty(s.T(), authHeader)
	require.Equal(s.T(), "Bearer "+saToken, authHeader)
}

func (s *TestNotificationSuite) TestSend() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	tokenManager, err := manager.ReadTokenManagerFromContext(ctx)
	require.Nil(s.T(), err)

	// extract the token
	saToken := tokenManager.AuthServiceAccountToken()

	// create client
	cl, err := s.ns.createClientWithContextSigner(ctx)
	require.NoError(s.T(), err)

	s.T().Run("should send message", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Authorization", "Bearer "+saToken).
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(msgID)).
			Reply(202)

		//when
		err := s.ns.send(ctx, cl, msg)

		//then
		require.NoError(t, err)
	})

	s.T().Run("should fail to send message if client returned an error", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Authorization", "Bearer "+saToken).
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(msgID)).
			Reply(400).
			BodyString("something bad happened")

		//when
		err = s.ns.send(ctx, cl, msg)

		//then
		require.Error(t, err)
		assert.Equal(t, "unexpected response code: 400 Bad Request; response body: something bad happened", err.Error())
	})

	s.T().Run("should fail to send message if client returned an unexpected status", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Authorization", "Bearer "+saToken).
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(msgID)).
			Reply(500).
			BodyString("something went wrong")

		//when
		err = s.ns.send(ctx, cl, msg)

		//then
		require.Error(t, err)
		testsupport.AssertError(t, err, autherrors.InternalError{}, "unexpected response code: 500 Internal Server Error; response body: something went wrong")
	})
}

func (s *TestNotificationSuite) TestSendMessage() {
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	tokenManager, err := manager.ReadTokenManagerFromContext(ctx)
	require.Nil(s.T(), err)

	// extract the token
	saToken := tokenManager.AuthServiceAccountToken()

	s.T().Run("should send message", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Authorization", "Bearer "+saToken).
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(msgID)).
			Reply(202)

		//when
		err := s.ns.SendMessage(ctx, msg)

		//then
		require.NoError(t, err)
	})

	s.T().Run("should fail to send message if client returned an error", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Authorization", "Bearer "+saToken).
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(msgID)).
			Reply(400).
			BodyString("something bad happened")

		//when
		err = s.ns.SendMessage(ctx, msg)

		//then
		require.Error(t, err)
		assert.Equal(t, "unexpected response code: 400 Bad Request; response body: something bad happened", err.Error())
	})

	s.T().Run("should fail to send message if client returned an unexpected status", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Authorization", "Bearer "+saToken).
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			BodyString(WithPayload(msgID)).
			Reply(500).
			BodyString("something went wrong")

		//when
		err = s.ns.SendMessage(ctx, msg)

		//then
		require.Error(t, err)
		testsupport.AssertError(t, err, autherrors.InternalError{}, "unexpected response code: 500 Internal Server Error; response body: something went wrong")
	})
}

func (s *TestNotificationSuite) TestSendAsync() {
	// given
	ctx, _, reqID := tokentestsupport.ContextWithTokenAndRequestID(s.T())

	tokenManager, err := manager.ReadTokenManagerFromContext(ctx)
	require.Nil(s.T(), err)

	// extract the token
	saToken := tokenManager.AuthServiceAccountToken()

	config := &notificationURLConfig{
		ConfigurationData: s.Config,
		notificationURL:   "::::",
	}
	ns := NewNotificationService(nil, config).(*notificationServiceImpl)

	s.T().Run("should fail to send message for invalid notification url", func(t *testing.T) {
		//given
		msg := createMessage(uuid.NewV4())
		//when
		errs, e := ns.SendMessageAsync(ctx, msg)

		//then
		assert.Error(t, e)
		assert.Nil(t, errs)
	})

	s.T().Run("should fail to send messages for invalid notification url", func(t *testing.T) {
		//given
		msg := createMessage(uuid.NewV4())

		//when
		errs, e := ns.SendMessagesAsync(ctx, []notification.Message{msg})

		//then
		assert.Error(t, e)
		assert.Nil(t, errs)
	})

	s.T().Run("should report error to channel if client returned an error for sending message async", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			MatchHeader("Authorization", "Bearer "+saToken).
			BodyString(WithPayload(msgID)).
			Reply(400).
			BodyString("something bad happened")

		// when
		errs, e := s.ns.SendMessagesAsync(ctx, []notification.Message{msg}, rest.WithRoundTripper(http.DefaultTransport))
		err, ok := <-errs

		// then
		assert.NoError(t, e)
		assert.True(t, ok)
		require.Error(t, err)
		assert.Equal(t, "unexpected response code: 400 Bad Request; response body: something bad happened", err.Error())
	})

	s.T().Run("should report error to channel if client returned an unexpected status for sending messages async", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			MatchHeader("Authorization", "Bearer "+saToken).
			BodyString(WithPayload(msgID)).
			Reply(500).
			BodyString("something went wrong")

		//when
		errs, e := s.ns.SendMessagesAsync(ctx, []notification.Message{msg}, rest.WithRoundTripper(http.DefaultTransport))
		err, ok := <-errs

		//then
		assert.NoError(t, e)
		assert.True(t, ok)
		require.Error(t, err)
		testsupport.AssertError(t, err, autherrors.InternalError{}, "unexpected response code: 500 Internal Server Error; response body: something went wrong")
	})

	s.T().Run("should send messages async", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			Times(2).
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			MatchHeader("Authorization", "Bearer "+saToken).
			BodyString(WithPayload(msgID)).
			Reply(202)

		//when
		errs, e := s.ns.SendMessagesAsync(ctx, []notification.Message{msg, msg}, rest.WithRoundTripper(http.DefaultTransport))
		err, ok := <-errs

		//then
		assert.NoError(t, e)
		assert.False(t, ok)
		assert.NoError(t, err)
	})

	s.T().Run("should send message async", func(t *testing.T) {
		//given
		msgID := uuid.NewV4()
		msg := createMessage(msgID)

		defer gock.OffAll()
		gock.New("https://notification").
			Post("api/notify").
			MatchHeader("Content-Type", "application/json").
			MatchHeader("X-Request-Id", reqID).
			MatchHeader("Authorization", "Bearer "+saToken).
			BodyString(WithPayload(msgID)).
			Reply(202)

		//when
		errs, e := s.ns.SendMessageAsync(ctx, msg, rest.WithRoundTripper(http.DefaultTransport))
		err, ok := <-errs

		//then
		assert.NoError(t, e)
		assert.False(t, ok)
		assert.NoError(t, err)
	})
}

type notificationURLConfig struct {
	*configuration.ConfigurationData
	notificationURL string
}

func (c *notificationURLConfig) GetNotificationServiceURL() string {
	return c.notificationURL
}

func createMessage(messageID uuid.UUID) notification.Message {
	// create a message
	customAttributes := make(map[string]interface{})
	customAttributes["teamName"] = "notification"
	customAttributes["inviter"] = "Dipak Pawar"
	customAttributes["spaceName"] = "notification testing"
	customAttributes["acceptURL"] = "localhost/accept"

	targetId := "8bccc228-bba7-43ad-b077-15fbb9148f7f"

	return notification.Message{
		MessageID:   messageID,
		Custom:      customAttributes,
		TargetID:    targetId,
		MessageType: "invitation.team.noorg",
	}
}

func WithPayload(messageID uuid.UUID) string {
	return `{
			"data": {
				"attributes": {
				"custom": {
					"teamName": "notification",
					"inviter": "Dipak Pawar",
					"spaceName": "notification testing",
					"acceptURL": "localhost/accept"
					},
				"id": "8bccc228-bba7-43ad-b077-15fbb9148f7f",
				"type": "invitation.team.noorg"
				},
				"id": "` + messageID.String() + `",
				"type": "notifications"
			}}`
}

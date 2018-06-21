package service

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/configuration"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/notification"
	"github.com/fabric8-services/fabric8-auth/rest"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/test/token"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestNotification(t *testing.T) {
	suite.Run(t, &TestNotificationSuite{})
}

type TestNotificationSuite struct {
	testsuite.UnitTestSuite
	ns                 *notificationServiceImpl
	doer               *testsupport.DummyHttpDoer
	notificationConfig *notificationURLConfig
}

func (s *TestNotificationSuite) SetupSuite() {
	s.UnitTestSuite.SetupSuite()
	s.notificationConfig = &notificationURLConfig{ConfigurationData: *s.Config, notificationURL: "https://some.notification.io"}
	s.ns = NewNotificationService(nil, s.notificationConfig).(*notificationServiceImpl)
	doer := testsupport.NewDummyHttpDoer()
	s.ns.doer = doer
	s.doer = doer
}

func (s *TestNotificationSuite) TestDefaultDoer() {
	ts := NewNotificationService(nil, s.notificationConfig).(*notificationServiceImpl)
	assert.Equal(s.T(), ts.config, s.notificationConfig)
	assert.Equal(s.T(), ts.doer, rest.DefaultHttpDoer())
}

func (s *TestNotificationSuite) TestDevNullNotificationService() {
	ts := NewNotificationService(nil, &notificationURLConfig{})
	assert.Equal(s.T(), ts, &devNullNotificationService{})
	assert.Nil(s.T(), ts.SendAsync(nil, notification.Message{}))
	assert.Nil(s.T(), ts.SendMessagesAsync(nil, []notification.Message{}))
}

func (s *TestNotificationSuite) TestSendAsync() {
	// Fail if service URL is invalid

	ctx, _, _ := token.ContextWithTokenAndRequestID(s.T())
	config := &notificationURLConfig{ConfigurationData: *s.Config, notificationURL: "::::"}
	ns := NewNotificationService(nil, config).(*notificationServiceImpl)
	doer := testsupport.NewDummyHttpDoer()
	ns.doer = doer
	doer.Client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader([]byte{}))
	doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	msg := notification.Message{}
	err := ns.SendAsync(ctx, msg)
	assert.Error(s.T(), err)

	err = ns.SendMessagesAsync(ctx, []notification.Message{msg})
	assert.Error(s.T(), err)

	// OK
	ns.config = s.notificationConfig
	err = ns.SendAsync(ctx, msg)
	assert.NoError(s.T(), err)

	err = ns.SendMessagesAsync(ctx, []notification.Message{msg})
	assert.NoError(s.T(), err)
}

func (s *TestNotificationSuite) TestSend() {
	ctx, token, reqID := token.ContextWithTokenAndRequestID(s.T())

	// Create client
	cl, err := s.ns.createClientWithContextSigner(ctx)
	require.NoError(s.T(), err)

	// Create message
	custom := make(map[string]interface{})
	custom["key"] = "value"
	msg := notification.Message{MessageID: uuid.NewV4(), MessageType: "sometype", TargetID: "someTarget", Custom: custom}

	// Set up expected request
	s.doer.Client.Error = nil
	body := ioutil.NopCloser(bytes.NewReader([]byte{}))
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusOK}

	s.doer.Client.AssertRequest = func(req *http.Request) {
		assert.Equal(s.T(), "POST", req.Method)
		assert.Equal(s.T(), "https://some.notification.io/api/notify", req.URL.String())
		assert.Equal(s.T(), "Bearer "+token, req.Header.Get("Authorization"))
		assert.Equal(s.T(), reqID, req.Header.Get("X-Request-Id"))

		expectedBody := fmt.Sprintf("{\"data\":{\"attributes\":{\"custom\":{\"key\":\"value\"},\"id\":\"someTarget\",\"type\":\"sometype\"},\"id\":\"%s\",\"type\":\"notifications\"}}\n", msg.MessageID.String())
		assert.Equal(s.T(), expectedBody, rest.ReadBody(req.Body))
	}

	// OK
	err = s.ns.send(ctx, cl, msg)
	require.NoError(s.T(), err)

	// Fail if client returned an error
	s.doer.Client.Response = nil
	s.doer.Client.Error = errors.New("oopsie woopsie")
	err = s.ns.send(ctx, cl, msg)
	require.Error(s.T(), err)
	assert.Equal(s.T(), "oopsie woopsie", err.Error())

	// Fail if client returned unexpected status
	s.doer.Client.Response = &http.Response{Body: body, StatusCode: http.StatusInternalServerError, Status: "500"}
	s.doer.Client.Error = nil
	err = s.ns.send(ctx, cl, msg)
	require.Error(s.T(), err)
	testsupport.AssertError(s.T(), err, autherrors.InternalError{}, "unexpected response code: 500; response body: ")
}

type notificationURLConfig struct {
	configuration.ConfigurationData
	notificationURL string
}

func (c *notificationURLConfig) GetNotificationServiceURL() string {
	return c.notificationURL
}

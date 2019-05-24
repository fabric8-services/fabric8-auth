package service_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-auth/adminconsole/service"
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/errors"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
)

func TestAdminConsoleService(t *testing.T) {
	suite.Run(t, &TestAdminConsoleServiceSuite{})
}

type TestAdminConsoleServiceSuite struct {
	testsuite.UnitTestSuite
}

func (s *TestAdminConsoleServiceSuite) TestCreateAuditLog() {
	tm, err := manager.DefaultManager(s.Config)
	require.NoError(s.T(), err)
	saToken := tm.AuthServiceAccountToken()
	// s.T().Logf("SA Token= %s", saToken)
	svc := service.NewService(nil, s.Config)

	defer gock.Off()
	gock.Observe(gock.DumpRequest)
	gock.New("http://admin-console").
		Post("api/auditlogs/users/username_ok").
		MatchHeader("Authorization", "Bearer "+saToken).
		MatchHeader("Content-Type", "application/json").
		BodyString(payload).
		Reply(202)
	gock.New("http://admin-console").
		Post("api/auditlogs/users/username_fail").
		MatchHeader("Authorization", "Bearer "+saToken).
		MatchHeader("Content-Type", "application/json").
		BodyString(payload).
		Reply(500).BodyString("ouch")

	s.Run("ok", func() {
		// given
		ctx := context.Background()
		// when
		err := svc.CreateAuditLog(ctx, "username_ok", "user_deactivation")
		// then
		assert.NoError(s.T(), err)
	})

	s.Run("failure", func() {
		// given
		ctx := context.Background()
		// when
		err := svc.CreateAuditLog(ctx, "username_fail", "user_deactivation")
		// then
		require.Error(s.T(), err)
		testsupport.AssertError(s.T(), err, errors.InternalError{}, "failed to create audit log in admin console service: 500 Internal Server Error; response body: ouch")
	})
}

const payload = `{"data":{"attributes":{"event_params":null,"event_type":"user_deactivation"},"type":"audit_logs"}}`

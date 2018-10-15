package service

import (
	"net/http"
	"testing"

	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TestOSORegistrationAppWhiteBoxSuite struct {
	testsuite.UnitTestSuite
}

func TestOSORegistrationAppWhiteBox(t *testing.T) {
	suite.Run(t, &TestOSORegistrationAppWhiteBoxSuite{UnitTestSuite: testsuite.NewUnitTestSuite()})
}

func (s *TestOSORegistrationAppWhiteBoxSuite) TestDefaultClient() {
	client := NewOSORegistrationApp(nil)
	require.NotNil(s.T(), client)
	require.IsType(s.T(), &osoRegistrationApp{}, client)
	regApp := client.(*osoRegistrationApp)
	assert.Equal(s.T(), regApp.httpClient, http.DefaultClient)
}

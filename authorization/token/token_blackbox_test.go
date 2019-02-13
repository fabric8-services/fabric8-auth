package token_test

import (
	"github.com/fabric8-services/fabric8-auth/authorization/token"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type tokenBlackboxTest struct {
	testsuite.UnitTestSuite
}

func TestTokenBlackbox(t *testing.T) {
	suite.Run(t, &tokenBlackboxTest{})
}

func (s *tokenBlackboxTest) TestIsValidTokenType() {
	require.True(s.T(), token.IsValidTokenType("ACC"))
	require.True(s.T(), token.IsValidTokenType("REF"))
	require.True(s.T(), token.IsValidTokenType("RPT"))
	require.False(s.T(), token.IsValidTokenType("foo"))
}

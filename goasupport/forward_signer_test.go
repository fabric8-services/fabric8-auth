package goasupport_test

import (
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/goasupport"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/test/token"

	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/magiconair/properties/assert"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestForwardSigner(t *testing.T) {
	suite.Run(t, &TestForwardSignerSuite{})
}

type TestForwardSignerSuite struct {
	testsuite.UnitTestSuite
}

func (s *TestForwardSignerSuite) TestNewForwardSigner() {
	sub := uuid.NewV4().String()
	ctx, err := token.EmbedTokenInContext(sub, uuid.NewV4().String())
	require.NoError(s.T(), err)

	signer := goasupport.NewForwardSigner(ctx)
	require.NotNil(s.T(), signer)

	// Sign request
	req := &http.Request{Header: map[string][]string{}}
	err = signer.Sign(req)
	require.NoError(s.T(), err)

	// Check the token in Authorization header
	assert.Equal(s.T(), "Bearer "+goajwt.ContextJWT(ctx).Raw, req.Header.Get("Authorization"))
}

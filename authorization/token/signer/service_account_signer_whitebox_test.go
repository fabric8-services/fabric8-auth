package signer_test

import (
	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/authorization/token/signer"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	tokentestsupport "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"net/http"
	"testing"
)

func TestSigner(t *testing.T) {
	suite.Run(t, &TestSignerSuite{})
}

type TestSignerSuite struct {
	testsuite.UnitTestSuite
}

func (s *TestSignerSuite) TestServiceAccountSigner() {
	t := s.T()

	// create a context
	ctx := tokentestsupport.ContextWithTokenManager()
	manager, err := manager.ReadTokenManagerFromContext(ctx)
	require.Nil(t, err)

	// extract the token
	saToken := manager.AuthServiceAccountToken()

	// Generate signer with the context
	tokenSigner := signer.NewSATokenSigner(ctx)
	signer, err := tokenSigner.Signer()

	// Use the signer to add auth headers to a request
	req, err := http.NewRequest("GET", "http://example.com", nil)
	r, err := signer.TokenSource.Token()
	r.SetAuthHeader(req)

	// Verify if the Auth header has the initial token that was extracted.
	require.NotEmpty(t, req.Header.Get("Authorization"))
	require.Equal(t, "Bearer "+saToken, req.Header.Get("Authorization"))
}

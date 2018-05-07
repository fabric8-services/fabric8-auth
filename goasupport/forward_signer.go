package goasupport

import (
	"context"
	"net/http"

	goaclient "github.com/goadesign/goa/client"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
)

// JWTSigner represents a JWT signer
type JWTSigner struct {
	Token string
}

// Sign sets the Auth header
func (f JWTSigner) Sign(request *http.Request) error {
	request.Header.Set("Authorization", "Bearer "+f.Token)
	return nil
}

// NewForwardSigner returns a new signer which uses the token from the context
// If the caller context is used then the token from this context will be extracted and forwarded to the target Request
func NewForwardSigner(ctx context.Context) goaclient.Signer {
	return &JWTSigner{Token: goajwt.ContextJWT(ctx).Raw}
}

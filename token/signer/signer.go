package signer

import (
	"context"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"
	goaclient "github.com/goadesign/goa/client"
)

type SATokenSigner struct {
	ctx context.Context
}

func NewSATokenSigner(ctx context.Context) SATokenSigner {
	return SATokenSigner{ctx}
}

func (s *SATokenSigner) Signer() (*goaclient.JWTSigner, error) {
	return getServiceAccountSigner(s.ctx)
}

func getServiceAccountSigner(ctx context.Context) (*goaclient.JWTSigner, error) {
	serviceAccountToken, err := getServiceAccountToken(ctx)
	if err != nil {
		return nil, err
	}

	staticToken := goaclient.StaticToken{
		Value: serviceAccountToken,
	}
	jwtSigner := goaclient.JWTSigner{
		TokenSource: &goaclient.StaticTokenSource{
			StaticToken: &staticToken,
		},
	}
	return &jwtSigner, nil
}

func getServiceAccountToken(ctx context.Context) (string, error) {
	manager, err := token.ReadManagerFromContext(ctx)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"error": err,
		}, "unable to obtain service token")
		return "", err
	}
	return (*manager).AuthServiceAccountToken(), nil
}

package tokencontext

import (
	"context"

	"github.com/fabric8-services/fabric8-auth/log"
	logintokencontext "github.com/fabric8-services/fabric8-auth/login/tokencontext"
	"github.com/fabric8-services/fabric8-auth/token"

	errs "github.com/pkg/errors"
)

// ReadManagerFromContext extracts the token manager
func ReadManagerFromContext(ctx context.Context) (*token.Manager, error) {
	tm := logintokencontext.ReadTokenManagerFromContext(ctx)
	if tm == nil {
		log.Error(ctx, map[string]interface{}{
			"token": tm,
		}, "missing token manager")

		return nil, errs.New("Missing token manager")
	}
	return tm.(*token.Manager), nil
}

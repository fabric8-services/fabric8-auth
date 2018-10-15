package token

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/log"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/pkg/errors"
)

const (
	AuthServiceAccountID = "8f558668-4db7-4280-8e65-408bcb95f9d9"

	// Service Account Names

	Auth               = "fabric8-auth"
	WIT                = "fabric8-wit"
	OsoProxy           = "fabric8-oso-proxy"
	Tenant             = "fabric8-tenant"
	Notification       = "fabric8-notification"
	JenkinsIdler       = "fabric8-jenkins-idler"
	JenkinsProxy       = "fabric8-jenkins-proxy"
	OnlineRegistration = "online-registration"
	RhChe              = "rh-che"
	GeminiServer       = "fabric8-gemini-server"

	_ = iota

	//contextTokenManagerKey is a key that will be used to put and to get `tokenManager` from goa.context
	contextTokenManagerKey contextTMKey = iota

	// Token Statuses

	TOKEN_STATUS_DEPROVISIONED = 1
	TOKEN_STATUS_REVOKED       = 2
	TOKEN_STATUS_LOGGED_OUT    = 4
	TOKEN_STATUS_STALE         = 8

	TOKEN_TYPE_RPT     = "RPT"
	TOKEN_TYPE_ACCESS  = "ACC"
	TOKEN_TYPE_REFRESH = "REF"
)

// JSONKeys the remote keys encoded in a json document
type JSONKeys struct {
	Keys []interface{} `json:"keys"`
}

// ReadManagerFromContext extracts the token manager from the context
func ReadManagerFromContext(ctx context.Context) (*tokenManager, error) {
	tm := ReadTokenManagerFromContext(ctx)
	if tm == nil {
		log.Error(ctx, map[string]interface{}{
			"token": tm,
		}, "missing token manager")

		return nil, errors.New("missing token manager")
	}
	return tm.(*tokenManager), nil
}

type contextTMKey int

const ()

// ReadTokenManagerFromContext returns an interface that encapsulates the
// tokenManager extracted from context. This interface can be safely converted.
// Must have been set by ContextWithTokenManager ONLY.
func ReadTokenManagerFromContext(ctx context.Context) interface{} {
	return ctx.Value(contextTokenManagerKey)
}

// ContextWithTokenManager injects tokenManager in the context for every incoming request
// Accepts Token.Manager in order to make sure that correct object is set in the context.
// Only other possible value is nil
func ContextWithTokenManager(ctx context.Context, tm interface{}) context.Context {
	return context.WithValue(ctx, contextTokenManagerKey, tm)
}

// IsServiceAccount checks if the request is done by a
// Service account based on the JWT Token provided in context
func IsServiceAccount(ctx context.Context) bool {
	_, ok := extractServiceAccountName(ctx)
	return ok
}

func extractServiceAccountName(ctx context.Context) (string, bool) {
	token := goajwt.ContextJWT(ctx)
	if token == nil {
		return "", false
	}
	accountName := token.Claims.(jwt.MapClaims)["service_accountname"]
	if accountName == nil {
		return "", false
	}
	accountNameTyped, isString := accountName.(string)
	return accountNameTyped, isString
}

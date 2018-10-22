package token

import (
	"context"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"

	goajwt "github.com/goadesign/goa/middleware/security/jwt"
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

	// Token Statuses

	TOKEN_STATUS_DEPROVISIONED = 1
	TOKEN_STATUS_REVOKED       = 2
	TOKEN_STATUS_LOGGED_OUT    = 4
	TOKEN_STATUS_STALE         = 8

	TOKEN_TYPE_RPT     = "RPT"
	TOKEN_TYPE_ACCESS  = "ACC"
	TOKEN_TYPE_REFRESH = "REF"
)

// PrivateKey represents an RSA private key with a Key ID
type PrivateKey struct {
	KeyID string
	Key   *rsa.PrivateKey
}

// PublicKey represents an RSA public key with a Key ID
type PublicKey struct {
	KeyID string
	Key   *rsa.PublicKey
}

// JSONKeys the remote keys encoded in a json document
type JSONKeys struct {
	Keys []interface{} `json:"keys"`
}

// IsSpecificServiceAccount checks if the request is done by a service account listed in the names param
// based on the JWT Token provided in context
func IsSpecificServiceAccount(ctx context.Context, names ...string) bool {
	accountName, ok := extractServiceAccountName(ctx)
	if !ok {
		return false
	}
	for _, name := range names {
		if accountName == name {
			return true
		}
	}
	return false
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

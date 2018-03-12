package goamiddleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/token"

	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
)

// TokenContext is a new goa middleware that aims to extract the token from the
// Authorization header when possible. If the Authorization header is missing in the request,
// no error is returned. However, if the Authorization header contains a
// token, it will be stored it in the context.
func TokenContext(tokenManager token.Parser, scheme *goa.JWTSecurity) goa.Middleware {
	return func(nextHandler goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			// TODO: implement the QUERY string handler too
			if scheme.In != goa.LocHeader {
				log.Error(ctx, nil, fmt.Sprintf("whoops, security scheme with location (in) %q not supported", scheme.In))
				return fmt.Errorf("whoops, security scheme with location (in) %q not supported", scheme.In)
			}
			val := req.Header.Get(scheme.Name)
			if val != "" && strings.HasPrefix(strings.ToLower(val), "bearer ") {
				log.Debug(ctx, nil, "found header 'Authorization: Bearer JWT-token...'")
				incomingToken := strings.Split(val, " ")[1]
				log.Debug(ctx, nil, "extracted the incoming token %v ", incomingToken)

				token, err := tokenManager.Parse(ctx, incomingToken)
				if err != nil {
					errUnauthorized := goa.NewErrorClass("validation_failed", 401)
					log.Error(ctx, map[string]interface{}{"error": err}, "failed to handle JSON Web Token in TokenContext middleware")
					return errUnauthorized("token is invalid")
				}
				ctx = jwt.WithJWT(ctx, token)
			}

			return nextHandler(ctx, rw, req)
		}
	}
}

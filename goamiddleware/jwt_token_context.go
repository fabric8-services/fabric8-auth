package goamiddleware

import (
	"context"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/application"
	"net/http"
	"strings"

	"github.com/fabric8-services/fabric8-auth/authorization/token/manager"
	"github.com/fabric8-services/fabric8-auth/log"

	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware/security/jwt"
)

// TokenContext is a new goa middleware that aims to extract the token from the
// Authorization header when possible. If the Authorization header is missing in the request,
// no error is returned. However, if the Authorization header contains a
// token, it will be stored it in the context.
func TokenContext(app application.Application, tokenManager manager.TokenManager, scheme *goa.JWTSecurity) goa.Middleware {
	errUnauthorized := goa.NewErrorClass("token_validation_failed", 401)
	return func(nextHandler goa.Handler) goa.Handler {
		return handler(app, tokenManager, scheme, nextHandler, errUnauthorized)
	}
}

func handler(app application.Application, tokenManager manager.TokenManager, scheme *goa.JWTSecurity, nextHandler goa.Handler, errUnauthorized goa.ErrorClass) goa.Handler {
	return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
		// TODO: implement the QUERY string handler too
		if scheme.In != goa.LocHeader {
			log.Error(ctx, nil, fmt.Sprintf("whoops, security scheme with location (in) %q not supported", scheme.In))
			return fmt.Errorf("whoops, security scheme with location (in) %q not supported", scheme.In)
		}
		val := req.Header.Get(scheme.Name)
		if val != "" && strings.HasPrefix(strings.ToLower(val), "bearer ") { // let's be more permissive than the spec and not restrict to a (strict) `Bearer` type of authorization
			log.Debug(ctx, nil, "found header 'Authorization: Bearer JWT-token...'")
			incomingToken := strings.Split(val, " ")[1]
			log.Debug(ctx, nil, "extracted the incoming token %v ", incomingToken)

			token, err := tokenManager.Parse(ctx, incomingToken)
			if err != nil {
				log.Error(ctx, map[string]interface{}{"error": err}, "failed to handle JSON Web Token in TokenContext middleware")
				tokenManager.AddLoginRequiredHeader(rw)
				return errUnauthorized("token is invalid")
			}

			// If the token is *not* a service account token, then check if it is valid
			accountName := token.Claims.(jwtgo.MapClaims)["service_accountname"]
			if accountName == nil {
				err = app.TokenService().ValidateToken(context.Background(), token)
				if err != nil {
					log.Error(ctx, map[string]interface{}{"error": err}, "failed to validate JSON Web Token in TokenContext middleware")
					tokenManager.AddLoginRequiredHeader(rw)
					return errUnauthorized("token is invalid")
				}
			}

			ctx = jwt.WithJWT(ctx, token)
		}

		return nextHandler(ctx, rw, req)
	}
}

package test

import (
	"context"
	"golang.org/x/oauth2"
	"net/http"
	"time"

	account "github.com/fabric8-services/fabric8-auth/account/repository"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/space/authz"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/satori/go.uuid"
)

type dummySpaceAuthzService struct {
}

func (s *dummySpaceAuthzService) Authorize(ctx context.Context, entitlementEndpoint string, spaceID string) (bool, error) {
	return true, nil
}

func (s *dummySpaceAuthzService) Configuration() authz.AuthzConfiguration {
	return nil
}

// WithIdentity fills the context with token
// Token is filled using input Identity object
func WithIdentity(ctx context.Context, ident account.Identity) context.Context {
	token := fillClaimsWithIdentity(ident)
	return goajwt.WithJWT(ctx, token)
}

// WithAuthz fills the context with token
// Token is filled using input Identity object and resource authorization information
func WithAuthz(ctx context.Context, key interface{}, ident account.Identity, authz token.AuthorizationPayload) context.Context {
	token := fillClaimsWithIdentity(ident)
	token.Claims.(jwt.MapClaims)["authorization"] = authz
	token.Header["kid"] = "test-key"
	t, err := token.SignedString(key)
	if err != nil {
		panic(err.Error())
	}
	token.Raw = t
	return goajwt.WithJWT(ctx, token)
}

func fillClaimsWithIdentity(ident account.Identity) *jwt.Token {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims.(jwt.MapClaims)["sub"] = ident.ID.String()
	token.Claims.(jwt.MapClaims)["uuid"] = ident.ID.String()
	token.Claims.(jwt.MapClaims)["fullName"] = ident.User.FullName
	token.Claims.(jwt.MapClaims)["imageURL"] = ident.User.ImageURL
	token.Claims.(jwt.MapClaims)["iat"] = time.Now().Unix()
	return token
}

// WithIncompleteIdentity fills the context with token
// Token is filled using input Identity object but without the sub claim
func WithIncompleteIdentity(ctx context.Context, ident account.Identity) context.Context {
	token := fillIncompleteClaimsWithIdentity(ident)
	return goajwt.WithJWT(ctx, token)
}

func fillIncompleteClaimsWithIdentity(ident account.Identity) *jwt.Token {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims.(jwt.MapClaims)["imageURL"] = ident.User.ImageURL
	token.Claims.(jwt.MapClaims)["iat"] = time.Now().Unix()
	return token
}

func service(serviceName string, key interface{}, u account.Identity, authz *token.AuthorizationPayload) *goa.Service {
	svc := goa.New(serviceName)
	if authz == nil {
		svc.Context = WithIdentity(svc.Context, u)
	} else {
		svc.Context = WithAuthz(svc.Context, key, u, *authz)
	}
	svc.Context = tokencontext.ContextWithTokenManager(svc.Context, testtoken.TokenManager)
	return svc
}

// ServiceAsUser creates a new service and fill the context with input Identity
func ServiceAsUser(serviceName string, u account.Identity) *goa.Service {
	svc := service(serviceName, nil, u, nil)
	svc.Context = tokencontext.ContextWithSpaceAuthzService(svc.Context, &authz.KeycloakAuthzServiceManager{Service: &dummySpaceAuthzService{}})
	return svc
}

// ServiceAsUserWithIncompleteClaims creates a new service and fill the context with input Identity
func ServiceAsUserWithIncompleteClaims(serviceName string, u account.Identity) *goa.Service {
	svc := service(serviceName, nil, u, nil)
	svc.Context = WithIncompleteIdentity(svc.Context, u)
	return svc
}

// UnsecuredService creates a new service with token manager injected by without any identity in context
func UnsecuredService(serviceName string) *goa.Service {
	svc := goa.New(serviceName)
	svc.Context = tokencontext.ContextWithTokenManager(svc.Context, testtoken.TokenManager)
	svc.Context = tokencontext.ContextWithSpaceAuthzService(svc.Context, &authz.KeycloakAuthzServiceManager{Service: &dummySpaceAuthzService{}})
	return svc
}

// ServiceAsSpaceUser creates a new service and fill the context with input Identity and space authz service
func ServiceAsSpaceUser(serviceName string, u account.Identity, authzSrv authz.AuthzService) *goa.Service {
	svc := service(serviceName, nil, u, nil)
	svc.Context = tokencontext.ContextWithSpaceAuthzService(svc.Context, &authz.KeycloakAuthzServiceManager{Service: authzSrv})
	return svc
}

// ServiceAsServiceAccountUser generates the minimal service needed to satisfy the condition of being a service account.
func ServiceAsServiceAccountUser(serviceName string, u account.Identity) *goa.Service {
	svc := goa.New(serviceName)
	svc.Context = WithServiceAccountAuthz(svc.Context, testtoken.TokenManager, u)
	svc.Context = tokencontext.ContextWithTokenManager(svc.Context, testtoken.TokenManager)
	return svc
}

// WithServiceAccountAuthz fills the context with token
// Token is filled using input Identity object and resource authorization information
func WithServiceAccountAuthz(ctx context.Context, tokenManager token.Manager, ident account.Identity) context.Context {
	r := &goa.RequestData{
		Request: &http.Request{Host: "example.com"},
	}
	if ident.ID == uuid.Nil {
		ident.ID = uuid.NewV4()
	}
	token := tokenManager.GenerateUnsignedServiceAccountToken(r, ident.ID.String(), ident.Username)
	return goajwt.WithJWT(ctx, token)
}

// DummyOSORegistrationApp represents a mock OSOSubscriptionManager implementation
type DummyOSORegistrationApp struct {
	Status string
	Err    error
}

func (regApp *DummyOSORegistrationApp) LoadOSOSubscriptionStatus(ctx context.Context, config login.Configuration, keycloakToken oauth2.Token) (string, error) {
	return regApp.Status, regApp.Err
}

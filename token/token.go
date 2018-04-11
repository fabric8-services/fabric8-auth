package token

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fabric8-services/fabric8-auth/account"
	autherrors "github.com/fabric8-services/fabric8-auth/errors"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"
	authjwt "github.com/fabric8-services/fabric8-auth/token/jwt"
	"github.com/fabric8-services/fabric8-auth/token/tokencontext"

	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

const (
	AuthServiceAccountID = "8f558668-4db7-4280-8e65-408bcb95f9d9"

	// Service Account Names

	OsoProxy           = "fabric8-oso-proxy"
	Tenant             = "fabric8-tenant"
	Notification       = "fabric8-notification"
	JenkinsIdler       = "fabric8-jenkins-idler"
	JenkinsProxy       = "fabric8-jenkins-proxy"
	OnlineRegistration = "online-registration"
)

// configuration represents configuration needed to construct a token manager
type configuration interface {
	GetServiceAccountPrivateKey() ([]byte, string)
	GetDeprecatedServiceAccountPrivateKey() ([]byte, string)
	GetUserAccountPrivateKey() ([]byte, string)
	GetDeprecatedUserAccountPrivateKey() ([]byte, string)
	GetDevModePublicKey() (bool, []byte, string)
	IsPostgresDeveloperModeEnabled() bool
	GetAccessTokenExpiresIn() int64
	GetRefreshTokenExpiresIn() int64
}

// TokenClaims represents access token claims
type TokenClaims struct {
	Name          string                `json:"name"`
	Username      string                `json:"preferred_username"`
	GivenName     string                `json:"given_name"`
	FamilyName    string                `json:"family_name"`
	Email         string                `json:"email"`
	EmailVerified bool                  `json:"email_verified"`
	Company       string                `json:"company"`
	SessionState  string                `json:"session_state"`
	Approved      bool                  `json:"approved"`
	Authorization *AuthorizationPayload `json:"authorization"`
	jwt.StandardClaims
}

// AuthorizationPayload represents an authz payload in the rpt token
type AuthorizationPayload struct {
	Permissions []Permissions `json:"permissions"`
}

// Permissions represents a "permissions" in the AuthorizationPayload
type Permissions struct {
	ResourceSetName *string `json:"resource_set_name"`
	ResourceSetID   *string `json:"resource_set_id"`
}

// Parser parses a token and exposes the public keys for the Goa JWT middleware.
type Parser interface {
	Parse(ctx context.Context, tokenString string) (*jwt.Token, error)
	PublicKeys() []*rsa.PublicKey
}

// Manager generate and find auth token information
type Manager interface {
	Parser
	Locate(ctx context.Context) (uuid.UUID, error)
	ParseToken(ctx context.Context, tokenString string) (*TokenClaims, error)
	ParseTokenWithMapClaims(ctx context.Context, tokenString string) (jwt.MapClaims, error)
	PublicKey(keyID string) *rsa.PublicKey
	JSONWebKeys() authjwt.JSONKeys
	PemKeys() authjwt.JSONKeys
	AuthServiceAccountToken(req *goa.RequestData) (string, error)
	GenerateServiceAccountToken(req *goa.RequestData, saID string, saName string) (string, error)
	GenerateUnsignedServiceAccountToken(req *goa.RequestData, saID string, saName string) *jwt.Token
	GenerateUserToken(ctx context.Context, keycloakToken oauth2.Token, identity *account.Identity) (*oauth2.Token, error)
	GenerateUserTokenForIdentity(ctx context.Context, identity account.Identity, offlineToken bool) (*oauth2.Token, error)
	ConvertTokenSet(tokenSet TokenSet) *oauth2.Token
	ConvertToken(oauthToken oauth2.Token) (*TokenSet, error)
}

type tokenManager struct {
	publicKeysMap            map[string]*rsa.PublicKey
	publicKeys               []*authjwt.PublicKey
	serviceAccountPrivateKey *authjwt.PrivateKey
	userAccountPrivateKey    *authjwt.PrivateKey
	jsonWebKeys              authjwt.JSONKeys
	pemKeys                  authjwt.JSONKeys
	serviceAccountToken      string
	serviceAccountLock       sync.RWMutex
	config                   configuration
}

// NewManager returns a new token Manager for handling tokens
func NewManager(config configuration) (Manager, error) {
	tm := &tokenManager{
		publicKeysMap: map[string]*rsa.PublicKey{},
	}
	tm.config = config

	// Load the user account private key and add it to the manager.
	// Extract the public key from it and add it to the map of public keys.
	var err error
	key, kid := config.GetUserAccountPrivateKey()
	deprecatedKey, deprecatedKid := config.GetDeprecatedUserAccountPrivateKey()
	tm.userAccountPrivateKey, err = LoadPrivateKey(tm, key, kid, deprecatedKey, deprecatedKid)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to load user account private keys")
		return nil, err
	}
	// Load the service account private key and add it to the manager.
	// Extract the public key from it and add it to the map of public keys.
	key, kid = config.GetServiceAccountPrivateKey()
	deprecatedKey, deprecatedKid = config.GetDeprecatedServiceAccountPrivateKey()
	tm.serviceAccountPrivateKey, err = LoadPrivateKey(tm, key, kid, deprecatedKey, deprecatedKid)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to load service account private keys")
		return nil, err
	}

	// Load Keycloak public key if run in dev mode.
	devMode, key, kid := config.GetDevModePublicKey()
	if devMode {
		rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
		if err != nil {
			log.Error(nil, map[string]interface{}{"err": err}, "unable to load dev mode public key")
			return nil, err
		}
		tm.publicKeysMap[kid] = rsaKey
		tm.publicKeys = append(tm.publicKeys, &authjwt.PublicKey{KeyID: kid, Key: rsaKey})
		log.Info(nil, map[string]interface{}{"kid": kid}, "dev mode public key added")
	}

	// Convert public keys to JWK format
	jsonWebKeys, err := toJSONWebKeys(tm.publicKeys)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to convert public keys to JSON Web Keys")
		return nil, errors.New("unable to convert public keys to JSON Web Keys")
	}
	tm.jsonWebKeys = jsonWebKeys

	// Convert public keys to PEM format
	jsonKeys, err := toPemKeys(tm.publicKeys)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to convert public keys to PEM Keys")
		return nil, errors.New("unable to convert public keys to PEM Keys")
	}
	tm.pemKeys = jsonKeys

	return tm, nil
}

// LoadPrivateKey loads a private key and a deprecated private key.
// Extracts public keys from them and adds them to the manager
// Returns the loaded private key.
func LoadPrivateKey(tm *tokenManager, key []byte, kid string, deprecatedKey []byte, deprecatedKid string) (*authjwt.PrivateKey, error) {
	if len(key) == 0 || kid == "" {
		log.Error(nil, map[string]interface{}{
			"kid":        kid,
			"key_length": len(key),
		}, "private key or its ID are not set up")
		return nil, errors.New("private key or its ID are not set up")
	}

	// Load the private key. Extract the public key from it
	rsaServiceAccountKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		log.Error(nil, map[string]interface{}{"err": err}, "unable to parse private key")
		return nil, err
	}
	privateKey := &authjwt.PrivateKey{KeyID: kid, Key: rsaServiceAccountKey}
	pk := &rsaServiceAccountKey.PublicKey
	tm.publicKeysMap[kid] = pk
	tm.publicKeys = append(tm.publicKeys, &authjwt.PublicKey{KeyID: kid, Key: pk})
	log.Info(nil, map[string]interface{}{"kid": kid}, "public key added")

	// Extract public key from the deprecated key if any and add it to the manager
	if len(deprecatedKey) == 0 || deprecatedKid == "" {
		log.Debug(nil, map[string]interface{}{
			"kid":        deprecatedKid,
			"key_length": len(deprecatedKey),
		}, "no deprecated private key found")
	} else {
		rsaServiceAccountKey, err := jwt.ParseRSAPrivateKeyFromPEM(deprecatedKey)
		if err != nil {
			log.Error(nil, map[string]interface{}{"err": err}, "unable to parse deprecated private key")
			return nil, err
		}
		pk := &rsaServiceAccountKey.PublicKey
		tm.publicKeysMap[deprecatedKid] = pk
		tm.publicKeys = append(tm.publicKeys, &authjwt.PublicKey{KeyID: deprecatedKid, Key: pk})
		log.Info(nil, map[string]interface{}{"kid": deprecatedKid}, "deprecated public key added")
	}
	return privateKey, nil
}

func toPem(key *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubASN1), nil
}

func toJSONWebKeys(publicKeys []*authjwt.PublicKey) (authjwt.JSONKeys, error) {
	var result []interface{}
	for _, key := range publicKeys {
		jwk := jose.JSONWebKey{Key: key.Key, KeyID: key.KeyID, Algorithm: "RS256", Use: "sig"}
		keyData, err := jwk.MarshalJSON()
		if err != nil {
			return authjwt.JSONKeys{}, err
		}
		var raw interface{}
		err = json.Unmarshal(keyData, &raw)
		if err != nil {
			return authjwt.JSONKeys{}, err
		}
		result = append(result, raw)
	}
	return authjwt.JSONKeys{Keys: result}, nil
}

// JSONWebKeys returns all the public keys in JSON Web Keys format
func (mgm *tokenManager) JSONWebKeys() authjwt.JSONKeys {
	return mgm.jsonWebKeys
}

// PemKeys returns all the public keys in PEM-like format (PEM without header and footer)
func (mgm *tokenManager) PemKeys() authjwt.JSONKeys {
	return mgm.pemKeys
}

func toPemKeys(publicKeys []*authjwt.PublicKey) (authjwt.JSONKeys, error) {
	var pemKeys []interface{}
	for _, key := range publicKeys {
		keyData, err := toPem(key.Key)
		if err != nil {
			return authjwt.JSONKeys{}, err
		}
		rawPemKey := map[string]interface{}{"kid": key.KeyID, "key": keyData}
		pemKeys = append(pemKeys, rawPemKey)
	}
	return authjwt.JSONKeys{Keys: pemKeys}, nil
}

// ParseToken parses token claims
func (mgm *tokenManager) ParseToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, mgm.keyFunction(ctx))
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(*TokenClaims)
	if token.Valid {
		return claims, nil
	}
	return nil, errors.WithStack(errors.New("token is not valid"))
}

// ParseTokenWithMapClaims parses token claims
func (mgm *tokenManager) ParseTokenWithMapClaims(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, mgm.keyFunction(ctx))
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(jwt.MapClaims)
	if token.Valid {
		return claims, nil
	}
	return nil, errors.WithStack(errors.New("token is not valid"))
}

func (mgm *tokenManager) keyFunction(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"]
		if kid == nil {
			log.Error(ctx, map[string]interface{}{}, "There is no 'kid' header in the token")
			return nil, errors.New("There is no 'kid' header in the token")
		}
		key := mgm.PublicKey(fmt.Sprintf("%s", kid))
		if key == nil {
			log.Error(ctx, map[string]interface{}{
				"kid": kid,
			}, "There is no public key with such ID")
			return nil, errors.New(fmt.Sprintf("There is no public key with such ID: %s", kid))
		}
		return key, nil
	}
}

func (mgm *tokenManager) Locate(ctx context.Context) (uuid.UUID, error) {
	token := goajwt.ContextJWT(ctx)
	if token == nil {
		return uuid.UUID{}, errors.New("Missing token") // TODO, make specific tokenErrors
	}
	id := token.Claims.(jwt.MapClaims)["sub"]
	if id == nil {
		return uuid.UUID{}, errors.New("Missing sub")
	}
	idTyped, err := uuid.FromString(id.(string))
	if err != nil {
		return uuid.UUID{}, errors.New("uuid not of type string")
	}
	return idTyped, nil
}

// PublicKey returns the public key by the ID
func (mgm *tokenManager) PublicKey(keyID string) *rsa.PublicKey {
	return mgm.publicKeysMap[keyID]
}

// PublicKeys returns all the public keys
func (mgm *tokenManager) PublicKeys() []*rsa.PublicKey {
	keys := make([]*rsa.PublicKey, 0, len(mgm.publicKeysMap))
	for _, key := range mgm.publicKeys {
		keys = append(keys, key.Key)
	}
	return keys
}

// AuthServiceAccountToken returns the service account token which authenticates the Auth service
func (mgm *tokenManager) AuthServiceAccountToken(req *goa.RequestData) (string, error) {
	var token string
	if token = mgm.getServiceAccountToken(); token == "" {
		return mgm.initServiceAccountToken(req)
	}
	return token, nil
}

func (mgm *tokenManager) getServiceAccountToken() string {
	mgm.serviceAccountLock.RLock()
	defer mgm.serviceAccountLock.RUnlock()
	return mgm.serviceAccountToken
}

func (mgm *tokenManager) initServiceAccountToken(req *goa.RequestData) (string, error) {
	mgm.serviceAccountLock.Lock()
	defer mgm.serviceAccountLock.Unlock()

	tokenStr, err := mgm.GenerateServiceAccountToken(req, AuthServiceAccountID, "fabric8-auth")
	if err != nil {
		return "", errors.WithStack(err)
	}
	mgm.serviceAccountToken = tokenStr

	return mgm.serviceAccountToken, nil
}

// GenerateServiceAccountToken generates and signs a new Service Account Token (Protection API Token)
func (mgm *tokenManager) GenerateServiceAccountToken(req *goa.RequestData, saID string, saName string) (string, error) {
	token := mgm.GenerateUnsignedServiceAccountToken(req, saID, saName)
	tokenStr, err := token.SignedString(mgm.serviceAccountPrivateKey.Key)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return tokenStr, nil
}

// GenerateUnsignedServiceAccountToken generates an unsigned Service Account Token (Protection API Token)
func (mgm *tokenManager) GenerateUnsignedServiceAccountToken(req *goa.RequestData, saID string, saName string) *jwt.Token {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = mgm.serviceAccountPrivateKey.KeyID
	claims := token.Claims.(jwt.MapClaims)
	claims["service_accountname"] = saName
	claims["sub"] = saID
	claims["jti"] = uuid.NewV4().String()
	claims["iat"] = time.Now().Unix()
	claims["iss"] = rest.AbsoluteURL(req, "", nil)
	claims["scopes"] = []string{"uma_protection"}
	return token
}

// GenerateUserToken generates an OAuth2 user token for the given identity based on the Keycloak token
func (mgm *tokenManager) GenerateUserToken(ctx context.Context, keycloakToken oauth2.Token, identity *account.Identity) (*oauth2.Token, error) {
	unsignedAccessToken, err := mgm.GenerateUnsignedUserAccessToken(ctx, keycloakToken.AccessToken, identity)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	accessToken, err := unsignedAccessToken.SignedString(mgm.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	unsignedRefreshToken, err := mgm.GenerateUnsignedUserRefreshToken(ctx, keycloakToken.RefreshToken, identity)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	refreshToken, err := unsignedRefreshToken.SignedString(mgm.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       keycloakToken.Expiry,
		TokenType:    "bearer",
	}

	// Derivative OAuth2 claims "expires_in" and "refresh_expires_in"
	extra := make(map[string]interface{})
	expiresIn := keycloakToken.Extra("expires_in")
	if expiresIn != nil {
		extra["expires_in"] = expiresIn
	}
	refreshExpiresIn := keycloakToken.Extra("refresh_expires_in")
	if refreshExpiresIn != nil {
		extra["refresh_expires_in"] = refreshExpiresIn
	}
	notBeforePolicy := keycloakToken.Extra("not_before_policy")
	if notBeforePolicy != nil {
		extra["not_before_policy"] = notBeforePolicy
	}
	if len(extra) > 0 {
		token = token.WithExtra(extra)
	}

	return token, nil
}

// GenerateUserTokenForIdentity generates an OAuth2 user token for the given identity
func (mgm *tokenManager) GenerateUserTokenForIdentity(ctx context.Context, identity account.Identity, offlineToken bool) (*oauth2.Token, error) {
	nowTime := time.Now().Unix()
	unsignedAccessToken, err := mgm.GenerateUnsignedUserAccessTokenForIdentity(ctx, identity)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	accessToken, err := unsignedAccessToken.SignedString(mgm.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	unsignedRefreshToken, err := mgm.GenerateUnsignedUserRefreshTokenForIdentity(ctx, identity, offlineToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	refreshToken, err := unsignedRefreshToken.SignedString(mgm.userAccountPrivateKey.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var nbf int64

	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Expiry:       time.Unix(nowTime+mgm.config.GetAccessTokenExpiresIn(), 0),
		TokenType:    "bearer",
	}

	// Derivative OAuth2 claims "expires_in" and "refresh_expires_in"
	extra := make(map[string]interface{})
	extra["expires_in"] = mgm.config.GetAccessTokenExpiresIn()
	extra["refresh_expires_in"] = mgm.config.GetRefreshTokenExpiresIn()
	extra["not_before_policy"] = nbf

	token = token.WithExtra(extra)

	return token, nil
}

// GenerateUnsignedUserAccessToken generates an unsigned OAuth2 user access token for the given identity based on the Keycloak token
func (mgm *tokenManager) GenerateUnsignedUserAccessToken(ctx context.Context, keycloakAccessToken string, identity *account.Identity) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = mgm.userAccountPrivateKey.KeyID

	kcClaims, err := mgm.ParseToken(ctx, keycloakAccessToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req := goa.ContextRequest(ctx)
	if req == nil {
		return nil, errors.New("missing request in context")
	}

	authOpenshiftIO := rest.AbsoluteURL(req, "", mgm.config)
	openshiftIO, err := rest.ReplaceDomainPrefixInAbsoluteURL(req, "", "", mgm.config)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = uuid.NewV4().String()
	claims["exp"] = kcClaims.ExpiresAt
	claims["nbf"] = kcClaims.NotBefore
	claims["iat"] = kcClaims.IssuedAt
	claims["iss"] = kcClaims.Issuer
	claims["aud"] = kcClaims.Audience
	claims["typ"] = "Bearer"
	claims["auth_time"] = kcClaims.IssuedAt
	claims["approved"] = identity != nil && !identity.User.Deprovisioned && kcClaims.Approved
	if identity != nil {
		claims["sub"] = identity.ID.String()
		claims["email_verified"] = identity.User.EmailVerified
		claims["name"] = identity.User.FullName
		claims["preferred_username"] = identity.Username
		firstName, lastName := account.SplitFullName(identity.User.FullName)
		claims["given_name"] = firstName
		claims["family_name"] = lastName
		claims["email"] = identity.User.Email
	} else {
		claims["sub"] = kcClaims.Subject
		claims["email_verified"] = kcClaims.EmailVerified
		claims["name"] = kcClaims.Name
		claims["preferred_username"] = kcClaims.Username
		claims["given_name"] = kcClaims.GivenName
		claims["family_name"] = kcClaims.FamilyName
		claims["email"] = kcClaims.Email
	}

	claims["allowed-origins"] = []string{
		authOpenshiftIO,
		openshiftIO,
	}

	claims["azp"] = kcClaims.Audience
	claims["session_state"] = kcClaims.SessionState
	claims["acr"] = "0"

	realmAccess := make(map[string]interface{})
	realmAccess["roles"] = []string{"uma_authorization"}
	claims["realm_access"] = realmAccess

	resourceAccess := make(map[string]interface{})
	broker := make(map[string]interface{})
	broker["roles"] = []string{"read-token"}
	resourceAccess["broker"] = broker

	account := make(map[string]interface{})
	account["roles"] = []string{"manage-account", "manage-account-links", "view-profile"}
	resourceAccess["account"] = account

	claims["resource_access"] = resourceAccess

	return token, nil
}

// GenerateUnsignedUserAccessTokenForIdentity generates an unsigned OAuth2 user access token for the given identity
func (mgm *tokenManager) GenerateUnsignedUserAccessTokenForIdentity(ctx context.Context, identity account.Identity) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = mgm.userAccountPrivateKey.KeyID

	req := goa.ContextRequest(ctx)
	if req == nil {
		return nil, errors.New("missing request in context")
	}

	authOpenshiftIO := rest.AbsoluteURL(req, "", mgm.config)
	openshiftIO, err := rest.ReplaceDomainPrefixInAbsoluteURL(req, "", "", mgm.config)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = uuid.NewV4().String()
	iat := time.Now().Unix()
	claims["exp"] = iat + mgm.config.GetAccessTokenExpiresIn()
	claims["nbf"] = 0
	claims["iat"] = iat
	claims["iss"] = authOpenshiftIO
	claims["aud"] = openshiftIO
	claims["typ"] = "Bearer"
	claims["auth_time"] = iat // TODO should use the time when user actually logged-in the last time. Will need to get this time from the RHD token
	claims["approved"] = !identity.User.Deprovisioned
	claims["sub"] = identity.ID.String()
	claims["email_verified"] = identity.User.EmailVerified
	claims["name"] = identity.User.FullName
	claims["preferred_username"] = identity.Username
	firstName, lastName := account.SplitFullName(identity.User.FullName)
	claims["given_name"] = firstName
	claims["family_name"] = lastName
	claims["email"] = identity.User.Email
	claims["allowed-origins"] = []string{
		authOpenshiftIO,
		openshiftIO,
	}

	return token, nil
}

// GenerateUnsignedUserRefreshToken generates an unsigned OAuth2 user refresh token for the given identity based on the Keycloak token
func (mgm *tokenManager) GenerateUnsignedUserRefreshToken(ctx context.Context, keycloakRefreshToken string, identity *account.Identity) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = mgm.userAccountPrivateKey.KeyID

	kcClaims, err := mgm.ParseToken(ctx, keycloakRefreshToken)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req := goa.ContextRequest(ctx)
	if req == nil {
		return nil, errors.New("missing request in context")
	}

	typ := "Refresh"
	if kcClaims.ExpiresAt == 0 {
		typ = "Offline"
	}
	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = uuid.NewV4().String()
	claims["exp"] = kcClaims.ExpiresAt
	claims["nbf"] = kcClaims.NotBefore
	claims["iat"] = kcClaims.IssuedAt
	claims["iss"] = kcClaims.Issuer
	claims["aud"] = kcClaims.Audience
	claims["typ"] = typ
	claims["auth_time"] = 0

	if identity != nil {
		claims["sub"] = identity.ID.String()
	} else {
		claims["sub"] = kcClaims.Subject
	}

	claims["azp"] = kcClaims.Audience
	claims["session_state"] = kcClaims.SessionState

	return token, nil
}

// GenerateUnsignedUserRefreshTokenForIdentity generates an unsigned OAuth2 user refresh token for the given identity
func (mgm *tokenManager) GenerateUnsignedUserRefreshTokenForIdentity(ctx context.Context, identity account.Identity, offlineToken bool) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = mgm.userAccountPrivateKey.KeyID

	req := goa.ContextRequest(ctx)
	if req == nil {
		return nil, errors.New("missing request in context")
	}

	authOpenshiftIO := rest.AbsoluteURL(req, "", mgm.config)
	openshiftIO, err := rest.ReplaceDomainPrefixInAbsoluteURL(req, "", "", mgm.config)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = uuid.NewV4().String()
	iat := time.Now().Unix()
	var exp int64 // Offline tokens do not expire
	typ := "Offline"
	if !offlineToken {
		exp = iat + mgm.config.GetRefreshTokenExpiresIn()
		typ = "Refresh"
	}
	claims["exp"] = exp
	claims["nbf"] = 0
	claims["iat"] = iat
	claims["iss"] = authOpenshiftIO
	claims["aud"] = openshiftIO
	claims["typ"] = typ
	claims["auth_time"] = 0
	claims["sub"] = identity.ID.String()

	return token, nil
}

// ConvertTokenSet converts the token set to oauth2.Token
func (mgm *tokenManager) ConvertTokenSet(tokenSet TokenSet) *oauth2.Token {
	var accessToken, refreshToken, tokenType string
	extra := make(map[string]interface{})
	if tokenSet.AccessToken != nil {
		accessToken = *tokenSet.AccessToken
	}
	if tokenSet.RefreshToken != nil {
		refreshToken = *tokenSet.RefreshToken
	}
	if tokenSet.TokenType != nil {
		tokenType = *tokenSet.TokenType
	}
	var expire time.Time
	if tokenSet.ExpiresIn != nil {
		expire = time.Now().Add(time.Duration(*tokenSet.ExpiresIn) * time.Second)
		extra["expires_in"] = *tokenSet.ExpiresIn
	}
	if tokenSet.RefreshExpiresIn != nil {
		extra["refresh_expires_in"] = *tokenSet.RefreshExpiresIn
	}
	if tokenSet.NotBeforePolicy != nil {
		extra["not_before_policy"] = *tokenSet.NotBeforePolicy
	}

	oauth2Token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		Expiry:       expire,
	}
	oauth2Token = oauth2Token.WithExtra(extra)

	return oauth2Token
}

// ConvertToken converts the oauth2.Token to a token set
func (mgm *tokenManager) ConvertToken(oauthToken oauth2.Token) (*TokenSet, error) {

	tokenSet := &TokenSet{
		AccessToken:  &oauthToken.AccessToken,
		RefreshToken: &oauthToken.RefreshToken,
		TokenType:    &oauthToken.TokenType,
	}

	var err error
	tokenSet.ExpiresIn, err = mgm.extraInt(oauthToken, "expires_in")
	if err != nil {
		return nil, err
	}
	tokenSet.RefreshExpiresIn, err = mgm.extraInt(oauthToken, "refresh_expires_in")
	if err != nil {
		return nil, err
	}
	tokenSet.NotBeforePolicy, err = mgm.extraInt(oauthToken, "not_before_policy")
	if err != nil {
		return nil, err
	}

	return tokenSet, nil
}

func (mgm *tokenManager) extraInt(oauthToken oauth2.Token, claimName string) (*int64, error) {
	claim := oauthToken.Extra(claimName)
	if claim != nil {
		claimInt, err := NumberToInt(claim)
		if err != nil {
			return nil, err
		}
		return &claimInt, nil
	}
	return nil, nil
}

func (mgm *tokenManager) Parse(ctx context.Context, tokenString string) (*jwt.Token, error) {
	keyFunc := mgm.keyFunction(ctx)
	jwtToken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err,
		}, "unable to parse token")
		return nil, autherrors.NewUnauthorizedError(err.Error())
	}
	return jwtToken, nil
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

// CheckClaims checks if all the required claims are present in the access token
func CheckClaims(claims *TokenClaims) error {
	if claims.Subject == "" {
		return errors.New("subject claim not found in token")
	}
	_, err := uuid.FromString(claims.Subject)
	if err != nil {
		return errors.New("subject claim from token is not UUID " + err.Error())
	}
	if claims.Username == "" {
		return errors.New("username claim not found in token")
	}
	if claims.Email == "" {
		return errors.New("email claim not found in token")
	}
	return nil
}

// ReadManagerFromContext extracts the token manager
func ReadManagerFromContext(ctx context.Context) (*tokenManager, error) {
	tm := tokencontext.ReadTokenManagerFromContext(ctx)
	if tm == nil {
		log.Error(ctx, map[string]interface{}{
			"token": tm,
		}, "missing token manager")

		return nil, errors.New("missing token manager")
	}
	return tm.(*tokenManager), nil
}

// NumberToInt convert interface{} to int64
func NumberToInt(number interface{}) (int64, error) {
	switch v := number.(type) {
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case float32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	}
	result, err := strconv.ParseInt(fmt.Sprintf("%v", number), 10, 64)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// TokenSet represents a set of Access and Refresh tokens
type TokenSet struct {
	AccessToken      *string `json:"access_token,omitempty"`
	ExpiresIn        *int64  `json:"expires_in,omitempty"`
	NotBeforePolicy  *int64  `json:"not-before-policy,omitempty"`
	RefreshExpiresIn *int64  `json:"refresh_expires_in,omitempty"`
	RefreshToken     *string `json:"refresh_token,omitempty"`
	TokenType        *string `json:"token_type,omitempty"`
}

// ReadTokenSet extracts json with token data from the response
func ReadTokenSet(ctx context.Context, res *http.Response) (*TokenSet, error) {
	// Read the json out of the response body
	buf := new(bytes.Buffer)
	io.Copy(buf, res.Body)
	jsonString := strings.TrimSpace(buf.String())
	return ReadTokenSetFromJson(ctx, jsonString)
}

// ReadTokenSetFromJson parses json with a token set
func ReadTokenSetFromJson(ctx context.Context, jsonString string) (*TokenSet, error) {
	var token TokenSet
	err := json.Unmarshal([]byte(jsonString), &token)
	if err != nil {
		return nil, errors.Wrapf(err, "error when unmarshal json with access token %s ", jsonString)
	}
	return &token, nil
}

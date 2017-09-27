package token

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/fabric8-services/fabric8-auth/log"
	logintokencontext "github.com/fabric8-services/fabric8-auth/login/tokencontext"
	"github.com/fabric8-services/fabric8-auth/rest"

	errs "github.com/pkg/errors"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"net/url"
	"strconv"
)

const (
	ServiceAccountID = "8f558668-4db7-4280-8e65-408bcb95f9d9"
)

// configuration represents configuration needed to construct a token manager
type configuration interface {
	GetKeycloakEndpointCerts() string
	GetServiceAccountPrivateKey() ([]byte, string)
	GetDeprecatedServiceAccountPrivateKey() ([]byte, string)
}

type JsonKeys struct {
	Keys []interface{} `json:"keys"`
}

// TokenClaims represents access token claims
type TokenClaims struct {
	Name          string                `json:"name"`
	Username      string                `json:"preferred_username"`
	GivenName     string                `json:"given_name"`
	FamilyName    string                `json:"family_name"`
	Email         string                `json:"email"`
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

// Manager generate and find auth token information
type Manager interface {
	Locate(ctx context.Context) (uuid.UUID, error)
	ParseToken(ctx context.Context, tokenString string) (*TokenClaims, error)
	ParseTokenWithMapClaims(ctx context.Context, tokenString string) (jwt.MapClaims, error)
	PublicKey(keyID string) *rsa.PublicKey
	PublicKeys() []*rsa.PublicKey
	JsonWebKeys() JsonKeys
	PemKeys() JsonKeys
	ServiceAccountToken(req *goa.RequestData) (string, error)
}

// PrivateKey represents an RSA private key with a Key ID
type PrivateKey struct {
	KeyID string
	Key   *rsa.PrivateKey
}

type PublicKey struct {
	KeyID string
	Key   *rsa.PublicKey
}

type tokenManager struct {
	publicKeysMap            map[string]*rsa.PublicKey
	publicKeys               []*PublicKey
	serviceAccountPrivateKey *PrivateKey
	jsonWebKeys              JsonKeys
	pemKeys                  JsonKeys
	serviceAccountToken      string
	serviceAccountLock       sync.RWMutex
}

// NewManager returns a new token Manager for handling tokens
func NewManager(config configuration) (Manager, error) {
	// Load public keys from Keycloak and add them to the manager
	tm := &tokenManager{
		publicKeysMap: map[string]*rsa.PublicKey{},
	}

	keycloakKeys, err := FetchKeys(config.GetKeycloakEndpointCerts())
	if err != nil {
		log.Error(nil, map[string]interface{}{}, "unable to load Keycloak public keys")
		return nil, errors.New("unable to load Keycloak public keys")
	}
	for _, keycloakKey := range keycloakKeys {
		tm.publicKeysMap[keycloakKey.KeyID] = keycloakKey.Key
		tm.publicKeys = append(tm.publicKeys, &PublicKey{KeyID: keycloakKey.KeyID, Key: keycloakKey.Key})
		log.Info(nil, map[string]interface{}{
			"kid": keycloakKey.KeyID,
		}, "Public key added")
	}

	// Load the service account private key and add it to the manager.
	// Extract the public key from it and add it to the map of public keys.
	key, kid := config.GetServiceAccountPrivateKey()
	if len(key) == 0 || kid == "" {
		log.Error(nil, map[string]interface{}{
			"kid":        kid,
			"key_length": len(key),
		}, "Service account private key or its ID are not set up")
		return nil, errors.New("Service account private key or its ID are not set up")
	}
	rsaServiceAccountKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return nil, err
	}
	tm.serviceAccountPrivateKey = &PrivateKey{KeyID: kid, Key: rsaServiceAccountKey}
	pk := &rsaServiceAccountKey.PublicKey
	tm.publicKeysMap[kid] = pk
	tm.publicKeys = append(tm.publicKeys, &PublicKey{KeyID: kid, Key: pk})
	log.Info(nil, map[string]interface{}{
		"kid": kid,
	}, "Service account private key added")
	// Extract public key from deprecated service account private key if any and add it to the manager
	key, kid = config.GetDeprecatedServiceAccountPrivateKey()
	if len(key) == 0 || kid == "" {
		log.Debug(nil, map[string]interface{}{
			"kid":        kid,
			"key_length": len(key),
		}, "No deprecated service account private key found")
	} else {
		rsaServiceAccountKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
		if err != nil {
			return nil, err
		}
		pk := &rsaServiceAccountKey.PublicKey
		tm.publicKeysMap[kid] = pk
		tm.publicKeys = append(tm.publicKeys, &PublicKey{KeyID: kid, Key: pk})
		log.Info(nil, map[string]interface{}{
			"kid": kid,
		}, "Deprecated service account private key added")
	}

	jsonKeys, err := toJsonWebKeys(tm.publicKeys)
	if err != nil {
		log.Error(nil, map[string]interface{}{
			"err": err,
		}, "unable to convert public keys to JSON Web Keys")
		return nil, errors.New("unable to convert public keys to JSON Web Keys")
	}
	tm.jsonWebKeys = jsonKeys

	jsonKeys, err = toPemKeys(tm.publicKeys)
	if err != nil {
		log.Error(nil, map[string]interface{}{
			"err": err,
		}, "unable to convert public keys to PEM Keys")
		return nil, errors.New("unable to convert public keys to PEM Keys")
	}
	tm.pemKeys = jsonKeys

	return tm, nil
}

// NewManagerWithPublicKey returns a new token Manager for handling tokens with the only public key
func NewManagerWithPublicKey(id string, key *rsa.PublicKey) Manager {
	return &tokenManager{
		publicKeysMap: map[string]*rsa.PublicKey{id: key},
		publicKeys:    []*PublicKey{{KeyID: id, Key: key}},
	}
}

// FetchKeys fetches public JSON WEB Keys from a remote service
func FetchKeys(keysEndpointURL string) ([]*PublicKey, error) {
	req, err := http.NewRequest("GET", keysEndpointURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Error(nil, map[string]interface{}{
			"response_status": res.Status,
			"response_body":   rest.ReadBody(res.Body),
			"url":             keysEndpointURL,
		}, "unable to obtain public keys from remote service")
		return nil, errors.Errorf("unable to obtain public keys from remote service")
	}
	jsonString := rest.ReadBody(res.Body)
	keys, err := unmarshalKeys([]byte(jsonString))
	if err != nil {
		return nil, err
	}

	log.Info(nil, map[string]interface{}{
		"url":            keysEndpointURL,
		"number_of_keys": len(keys),
	}, "Public keys loaded")
	return keys, nil
}

func unmarshalKeys(jsonData []byte) ([]*PublicKey, error) {
	var keys []*PublicKey
	var raw JsonKeys
	err := json.Unmarshal(jsonData, &raw)
	if err != nil {
		return nil, err
	}
	for _, key := range raw.Keys {
		jsonKeyData, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		publicKey, err := unmarshalKey(jsonKeyData)
		if err != nil {
			return nil, err
		}
		keys = append(keys, publicKey)
	}
	return keys, nil
}

func unmarshalKey(jsonData []byte) (*PublicKey, error) {
	var key *jose.JSONWebKey
	key = &jose.JSONWebKey{}
	err := key.UnmarshalJSON(jsonData)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.Key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Key is not an *rsa.PublicKey")
	}
	return &PublicKey{key.KeyID, rsaKey}, nil
}

func toPem(key *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubASN1), nil
}

func toJsonWebKeys(publicKeys []*PublicKey) (JsonKeys, error) {
	var keys []interface{}
	for _, key := range publicKeys {
		jwk := jose.JSONWebKey{Key: key.Key, KeyID: key.KeyID, Algorithm: "RS256", Use: "sig"}
		keyData, err := jwk.MarshalJSON()
		if err != nil {
			return JsonKeys{}, err
		}
		var raw interface{}
		err = json.Unmarshal(keyData, &raw)
		if err != nil {
			return JsonKeys{}, err
		}
		keys = append(keys, raw)
	}
	return JsonKeys{Keys: keys}, nil
}

// JsonWebKeys returns all the public keys in JSON Web Keys format
func (mgm *tokenManager) JsonWebKeys() JsonKeys {
	return mgm.jsonWebKeys
}

// PemKeys returns all the public keys in PEM-like format (PEM without header and footer)
func (mgm *tokenManager) PemKeys() JsonKeys {
	return mgm.pemKeys
}

func toPemKeys(publicKeys []*PublicKey) (JsonKeys, error) {
	var pemKeys []interface{}
	for _, key := range publicKeys {
		keyData, err := toPem(key.Key)
		if err != nil {
			return JsonKeys{}, err
		}
		rawPemKey := map[string]interface{}{"kid": key.KeyID, "key": keyData}
		pemKeys = append(pemKeys, rawPemKey)
	}
	return JsonKeys{Keys: pemKeys}, nil
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

// ServiceAccountToken returns the service account token which authenticates the Auth service
func (mgm *tokenManager) ServiceAccountToken(req *goa.RequestData) (string, error) {
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
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = mgm.serviceAccountPrivateKey.KeyID
	token.Claims.(jwt.MapClaims)["service_accountname"] = "auth"
	token.Claims.(jwt.MapClaims)["sub"] = ServiceAccountID
	token.Claims.(jwt.MapClaims)["jti"] = uuid.NewV4().String()
	token.Claims.(jwt.MapClaims)["iat"] = time.Now().Unix()
	token.Claims.(jwt.MapClaims)["iss"] = rest.AbsoluteURL(req, "")

	tokenStr, err := token.SignedString(mgm.serviceAccountPrivateKey.Key)
	if err != nil {
		return "", errors.WithStack(err)
	}
	mgm.serviceAccountToken = tokenStr

	return mgm.serviceAccountToken, nil
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
	tm := logintokencontext.ReadTokenManagerFromContext(ctx)
	if tm == nil {
		log.Error(ctx, map[string]interface{}{
			"token": tm,
		}, "missing token manager")

		return nil, errs.New("missing token manager")
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

// EncodeToken encodes token
func EncodeToken(ctx context.Context, referrer *url.URL, outhToken *oauth2.Token) error {
	str := outhToken.Extra("expires_in")
	var expiresIn interface{}
	var refreshExpiresIn interface{}
	var err error
	expiresIn, err = NumberToInt(str)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"expires_in": str,
			"err":        err,
		}, "unable to parse expires_in claim")
		return errs.WithStack(errors.New("unable to parse expires_in claim to integer: " + err.Error()))
	}
	str = outhToken.Extra("refresh_expires_in")
	refreshExpiresIn, err = NumberToInt(str)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"refresh_expires_in": str,
			"err":                err,
		}, "unable to parse expires_in claim")
		return errs.WithStack(errors.New("unable to parse refresh_expires_in claim to integer: " + err.Error()))
	}
	tokenData := &app.TokenData{
		AccessToken:      &outhToken.AccessToken,
		RefreshToken:     &outhToken.RefreshToken,
		TokenType:        &outhToken.TokenType,
		ExpiresIn:        &expiresIn,
		RefreshExpiresIn: &refreshExpiresIn,
	}
	b, err := json.Marshal(tokenData)
	if err != nil {
		return errs.WithStack(errors.New("cant marshal token data struct " + err.Error()))
	}

	parameters := referrer.Query()
	parameters.Add("token_json", string(b))
	referrer.RawQuery = parameters.Encode()

	return nil
}

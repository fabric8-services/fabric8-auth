package token

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	"crypto/x509"
	"encoding/base64"

	jwt "github.com/dgrijalva/jwt-go"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	jose "gopkg.in/square/go-jose.v2"
)

// configuration represents configuration needed to construct a token manager
type configuration interface {
	GetKeycloakEndpointCerts() string
	GetServiceAccountPrivateKey() ([]byte, string)
	GetDeprecatedServiceAccountPrivateKey() ([]byte, string)
}

type rawKeys struct {
	Keys []interface{} `json:"keys"`
}

type rawPemKeys struct {
	Keys []rawPemKey `json:"keys"`
}

type rawPemKey struct {
	Kid string `json:"kid"`
	Key string `json:"key"`
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
	PublicKey(kid string) *rsa.PublicKey
	PublicKeys() []*rsa.PublicKey
	JsonWebKeys() ([]byte, error)
	PemKeys() ([]byte, error)
}

// PrivateKey represents an RSA private key with a Key ID
type PrivateKey struct {
	KID string
	Key *rsa.PrivateKey
}

type publicKey struct {
	KID string
	Key *rsa.PublicKey
}

type tokenManager struct {
	publicKeysMap            map[string]*rsa.PublicKey
	publicKeys               []*publicKey
	serviceAccountPrivateKey *PrivateKey
	jsonWebKeys              *[]byte
	pemKeys                  *[]byte
}

// NewManager returns a new token Manager for handling tokens
func NewManager(config configuration) (Manager, error) {
	// Load public keys from Keycloak and add them to the manager
	tm := &tokenManager{
		publicKeysMap: map[string]*rsa.PublicKey{},
	}

	keycloakKeys, err := loadKeysFromKeycloak(config)
	if err != nil {
		log.Error(nil, map[string]interface{}{}, "unable to load Keycloak public keys")
		return nil, errors.New("unable to load Keycloak public keys")
	}
	for _, keycloakKey := range keycloakKeys {
		tm.publicKeysMap[keycloakKey.KID] = keycloakKey.Key
		tm.publicKeys = append(tm.publicKeys, &publicKey{KID: keycloakKey.KID, Key: keycloakKey.Key})
		log.Info(nil, map[string]interface{}{
			"kid": keycloakKey.KID,
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
	tm.serviceAccountPrivateKey = &PrivateKey{KID: kid, Key: rsaServiceAccountKey}
	pk := &rsaServiceAccountKey.PublicKey
	tm.publicKeysMap[kid] = pk
	tm.publicKeys = append(tm.publicKeys, &publicKey{KID: kid, Key: pk})
	log.Info(nil, map[string]interface{}{
		"kid": kid,
	}, "Service account private key added")
	// Extract public key from deprecated service account private key if any and add it the manager
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
		tm.publicKeys = append(tm.publicKeys, &publicKey{KID: kid, Key: pk})
		log.Info(nil, map[string]interface{}{
			"kid": kid,
		}, "Deprecated service account private key added")
	}

	return tm, nil
}

// NewManagerWithPublicKey returns a new token Manager for handling tokens with the only public key
func NewManagerWithPublicKey(id string, key *rsa.PublicKey) Manager {
	return &tokenManager{
		publicKeysMap: map[string]*rsa.PublicKey{id: key},
		publicKeys:    []*publicKey{{KID: id, Key: key}},
	}
}

func loadKeysFromKeycloak(config configuration) ([]*publicKey, error) {
	req, err := http.NewRequest("GET", config.GetKeycloakEndpointCerts(), nil)
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
		}, "unable to obtain keycloak public keys")
		return nil, errors.Errorf("unable to obtain keycloak public keys")
	}
	jsonString := rest.ReadBody(res.Body)
	keys, err := unmarshalKeys([]byte(jsonString))
	if err != nil {
		return nil, err
	}

	log.Info(nil, map[string]interface{}{
		"url":            config.GetKeycloakEndpointCerts(),
		"number_of_keys": len(keys),
	}, "Public keys loaded")
	return keys, nil
}

func unmarshalKeys(jsonData []byte) ([]*publicKey, error) {
	var keys []*publicKey
	var raw rawKeys
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

func unmarshalKey(jsonData []byte) (*publicKey, error) {
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
	return &publicKey{key.KeyID, rsaKey}, nil
}

func toPem(key *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubASN1), nil
}

// JsonWebKeys returns a JSON that contains an array of all the public keys in JSON Web Keys format
func (mgm *tokenManager) JsonWebKeys() ([]byte, error) {
	if mgm.jsonWebKeys != nil {
		return *mgm.jsonWebKeys, nil
	}
	var keys []interface{}
	for _, key := range mgm.publicKeys {
		jwk := jose.JSONWebKey{Key: key.Key, KeyID: key.KID, Algorithm: "RS256", Use: "sig"}
		keyData, err := jwk.MarshalJSON()
		if err != nil {
			return nil, err
		}
		var raw interface{}
		err = json.Unmarshal(keyData, &raw)
		if err != nil {
			return nil, err
		}
		keys = append(keys, raw)
	}
	keysData := rawKeys{Keys: keys}
	data, err := json.Marshal(keysData)
	if err != nil {
		return nil, err
	}
	mgm.jsonWebKeys = &data
	return data, nil
}

// PemKeys returns a JSON that contains an array of all the public keys in PEM format
func (mgm *tokenManager) PemKeys() ([]byte, error) {
	if mgm.pemKeys != nil {
		return *mgm.pemKeys, nil
	}
	var pemKeys []interface{}
	for _, key := range mgm.publicKeys {
		keyData, err := toPem(key.Key)
		if err != nil {
			return nil, err
		}
		pemKeys = append(pemKeys, rawPemKey{Kid: key.KID, Key: keyData})
	}
	keysData := rawKeys{Keys: pemKeys}
	data, err := json.Marshal(keysData)
	if err != nil {
		return nil, err
	}
	mgm.pemKeys = &data
	return data, nil
}

// ParseToken parses token claims
func (mgm *tokenManager) ParseToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
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
	})
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(*TokenClaims)
	if token.Valid {
		return claims, nil
	}
	return nil, errors.WithStack(errors.New("token is not valid"))
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
func (mgm *tokenManager) PublicKey(kid string) *rsa.PublicKey {
	return mgm.publicKeysMap[kid]
}

// PublicKeys returns all the public keys
func (mgm *tokenManager) PublicKeys() []*rsa.PublicKey {
	keys := make([]*rsa.PublicKey, 0, len(mgm.publicKeysMap))
	for _, key := range mgm.publicKeys {
		keys = append(keys, key.Key)
	}
	return keys
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

package jwk

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"

	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/rest"

	"gopkg.in/square/go-jose.v2"
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
	defer rest.CloseResponse(res)
	bodyString := rest.ReadBody(res.Body)
	if res.StatusCode != http.StatusOK {
		log.Error(nil, map[string]interface{}{
			"response_status": res.Status,
			"response_body":   bodyString,
			"url":             keysEndpointURL,
		}, "unable to obtain public keys from remote service")
		return nil, errors.Errorf("unable to obtain public keys from remote service")
	}
	keys, err := unmarshalKeys([]byte(bodyString))
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
	var raw JSONKeys
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

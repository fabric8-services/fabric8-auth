package jwk_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/fabric8-services/fabric8-auth/test"
	testsuite "github.com/fabric8-services/fabric8-auth/test/suite"
	"github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/fabric8-services/fabric8-auth/token/jwk"

	"bytes"
	"github.com/magiconair/properties/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
)

type TestFetchKeysSuite struct {
	testsuite.UnitTestSuite
}

func TestRunFetchKeysSuite(t *testing.T) {
	suite.Run(t, &TestFetchKeysSuite{UnitTestSuite: testsuite.NewUnitTestSuite()})
}

func (s *TestFetchKeysSuite) TestFetchKeys() {
	client := &test.DummyHttpClient{AssertRequest: func(req *http.Request) {
		assert.Equal(s.T(), "GET", req.Method)
		assert.Equal(s.T(), "https://openshift.io/keys", req.URL.String())
	}}
	keyLoader := jwk.KeyLoader{HttpClient: client}
	client.Response = responseOK()

	// All three keys are loaded
	loadedKeys, err := keyLoader.FetchKeys("https://openshift.io/keys")
	require.NoError(s.T(), err)
	require.NotNil(s.T(), loadedKeys)
	require.Len(s.T(), loadedKeys, 3)
	for _, key := range loadedKeys {
		pk := token.TokenManager.PublicKey(key.KeyID)
		require.NotNil(s.T(), pk)
		require.Equal(s.T(), pk, key.Key)
	}

	// Fail if the client returned an error
	client.Response = responseOK()
	client.Error = errors.New("something went wrong")
	_, err = keyLoader.FetchKeys("https://openshift.io/keys")
	require.Error(s.T(), err)
	assert.Equal(s.T(), err, client.Error)

	// Fail if the client returned an error
	client.Response = responseError()
	client.Error = nil
	_, err = keyLoader.FetchKeys("https://openshift.io/keys")
	require.Error(s.T(), err)
	assert.Equal(s.T(), err.Error(), "unable to obtain public keys from remote service")

	// Fail if the client returned incorrect JSON
	client.Response = responseIncorrectJSON()
	_, err = keyLoader.FetchKeys("https://openshift.io/keys")
	require.Error(s.T(), err)
	assert.Equal(s.T(), err.Error(), "unexpected end of JSON input")
}

func responseOK() *http.Response {
	body := ioutil.NopCloser(bytes.NewReader([]byte(keys)))
	return &http.Response{Body: body, StatusCode: http.StatusOK}
}

func responseError() *http.Response {
	body := ioutil.NopCloser(bytes.NewReader([]byte(keys)))
	return &http.Response{Body: body, StatusCode: http.StatusInternalServerError}
}

func responseIncorrectJSON() *http.Response {
	body := ioutil.NopCloser(bytes.NewReader([]byte("")))
	return &http.Response{Body: body, StatusCode: http.StatusOK}
}

var keys = `{
		        "keys": [
		          {
        		    "alg": "RS256",
		            "e": "AQAB",
        		    "kid": "aUGv8mQA85jg4V1DU8Uk1W0uKsxn187KQONAGl6AMtc",
		            "kty": "RSA",
        		    "n": "40yB6SNoU4SpWxTfG5ilu-BlLYikRyyEcJIGg__w_GyqtjvT_CVo92DRTh_DlrgwjSitmZrhauBnrCOoUBMin0_TXeSo3w2M5tEiiIFPbTDRf2jMfbSGEOke9O0USCCR-bM2TncrgZR74qlSwq38VCND4zHc89rAzqJ2LVM2aXkuBbO7TcgLNyooBrpOK9khVHAD64cyODAdJY4esUjcLdlcB7TMDGOgxGGn2RARU7-TUf32gZZbTMikbuPM5gXuzGlo_22ECbQSKuZpbGwgPIAZ5NN9QA4D1NRz9-KDoiXZ6deZTTVCrZykJJ6RyLNfRh-XS-6G5nvcqAmfBpyOWw",
		            "use": "sig"
        		  },
		          {
        		    "alg": "RS256",
		            "e": "AQAB",
        		    "kid": "9MLnViaRkhVj1GT9kpWUkwHIwUD-wZfUxR-3CpkE-Xs",
		            "kty": "RSA",
        		    "n": "nwrjH5iTSErw9xUptp6QSFoUfpHUXZ-PaslYSUrpLjw1q27ODSFwmhV4-dAaTMO5chFv_kM36H3ZOyA146nwxBobS723okFaIkshRrf6qgtD6coTHlVUSBTAcwKEjNn4C9jtEpyOl-eSgxhMzRH3bwTIFlLlVMiZf7XVE7P3yuOCpqkk2rdYVSpQWQWKU-ZRywJkYcLwjEYjc70AoNpjO5QnY-Exx98E30iEdPHZpsfNhsjh9Z7IX5TrMYgz7zBTw8-niO_uq3RBaHyIhDbvenbR9Q59d88lbnEeHKgSMe2RQpFR3rxFRkc_64Rn_bMuL_ptNowPqh1P-9GjYzWmPw",
		            "use": "sig"
		          },
        		  {
		            "alg": "RS256",
        		    "e": "AQAB",
		            "kid": "bNq-BCOR3ev-E6buGSaPrU-0SXX8whhDlmZ6geenkTE",
        		    "kty": "RSA",
		            "n": "vQ8p-HsTMrgcsuIMoOR1LXRhynL9YAU0qoDON6PLKCpdBv0Xy_jnsPjo5DrtUOijuJcID8CR7E0hYpY9MgK5H5pDFwC4lbUVENquHEVS_E0pQSKCIzSmORcIhjYW2-wKfDOVjeudZwdFBIxJ6KpIty_aF78hlUJZuvghFVqoHQYTq_DZOmKjS-PAVLw8FKE3wa_3WU0EkpP-iovRMCkllzxqrcLPIvx-T2gkwe0bn0kTvdMOhTLTN2tuvKrFpVUxVi8RM_V8PtgdKroxnES7SyUqK8rLO830jKJzAYrByQL-sdGuSqInIY_geahQHEGTwMI0CLj6zfhpjSgCflstvw",
        		    "use": "sig"
		          }
		        ]
      		}`

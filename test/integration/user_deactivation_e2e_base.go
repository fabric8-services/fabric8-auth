package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
	"github.com/stretchr/testify/require"
)

var (
	authBinary = "../../bin/auth"
	ago7days   = time.Now().Add(-7 * 24 * time.Hour)
	ago40days  = time.Now().Add(-40 * 24 * time.Hour)
)

type BaseSuite struct {
	gormtestsupport.DBTestSuite

	witServer          *httptest.Server
	notificationServer *httptest.Server
	tenantServer       *httptest.Server
	clusterServer      *httptest.Server
	cheServer          *httptest.Server
	regAppServer       *httptest.Server

	stopAuth      func()
	displayErrors func(t *testing.T)
}

func (s *BaseSuite) SetupTest(notificationDone, deactivateDone chan string) {
	s.DBTestSuite.SetupTest()
	// start mock server
	s.witServer = startServer(newWITServer(), 8080)
	s.notificationServer = startServer(newNotificationServer(notificationDone), 8082)
	s.tenantServer = startServer(newTenantServer(), 8090)
	s.clusterServer = startServer(newClusterServer(), 8083)
	s.cheServer = startServer(newCheServer(), 8091)
	s.regAppServer = startServer(newRegAppServer(deactivateDone), 8085)

	// start auth_service
	configFile := os.Getenv("AUTH_CONFIG_FILE_PATH")
	os.Setenv("AUTH_CONFIG_FILE_PATH", "e2e_test_config.yml")
	var cmd *exec.Cmd
	cmd, s.displayErrors = s.runAuthService()
	err := cmd.Start()
	require.NoError(s.T(), err)
	s.stopAuth = func() {
		_ = cmd.Process.Kill()
		log.Println("[Test runner] Auth service stopped")
		os.Setenv("AUTH_CONFIG_FILE_PATH", configFile)
		log.Println("[Test runner] Restored default config file in env")
	}
	log.Println("[Test runner] Auth service started")
}

func (s *BaseSuite) TearDownTest() {
	s.DBTestSuite.TearDownTest()
	s.displayErrors(s.T())
	// stop mock server
	stopServer(s.witServer)
	stopServer(s.notificationServer)
	stopServer(s.tenantServer)
	stopServer(s.clusterServer)
	stopServer(s.cheServer)
	stopServer(s.regAppServer)
	s.stopAuth()
}

func (s *BaseSuite) runAuthService(args ...string) (*exec.Cmd, func(*testing.T)) {
	cmd := exec.Command(authBinary, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	return cmd, func(t *testing.T) {
		if t.Failed() {
			displayAuthLogs(t, out)
		}
	}
}

func newRegAppServer(DeactivateDone chan string) func(rw http.ResponseWriter, r *http.Request) {
	saToken, _ := testtoken.TokenManager.GenerateServiceAccountToken(testsupport.TestOnlineRegistrationAppIdentity.ID.String(),
		testsupport.TestOnlineRegistrationAppIdentity.Username)

	return func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("[RegApp service] incoming request: %s %s\n", r.Method, r.URL.Path)
		username := extractUsername(r.URL.Path)
		url := fmt.Sprintf("http://127.0.0.1:8089/api/namedusers/%s/deactivate", username)
		req, _ := http.NewRequest(http.MethodPatch, url, nil)
		tokenHeader := fmt.Sprintf("Bearer %s", saToken)
		req.Header.Set("Authorization", tokenHeader)

		httpClient := http.Client{}
		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("[RegApp service] error occurred: %v\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
			log.Printf("[RegApp service] returning response with status: %d\n", http.StatusInternalServerError)
			return
		}
		userID := extractIDFromRegAppRequestPath(r.URL.Path)
		DeactivateDone <- userID
		log.Printf("[RegApp service] returning response with status: %d\n", res.StatusCode)
	}
}

func newNotificationServer(notificationDone chan string) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("[Notification service] incoming request: %s %s\n", r.Method, r.URL.Path)
		defer r.Body.Close()
		content, _ := ioutil.ReadAll(r.Body)
		identityID := extractIDFromNotificationPayload(content)
		notificationDone <- identityID
		rw.WriteHeader(http.StatusAccepted)
		log.Printf("[Notification service] returning response with status: %d\n", http.StatusAccepted)
	}
}

func newClusterServer() func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("[Cluster service] incoming request: %s %s\n", r.Method, r.URL.Path)
		_, _ = rw.Write([]byte(`{
		"data": [
			{
				"api-url": "starter-us-east-2",
				"app-dns": "b542.starter-us-east-2a.openshiftapps.com",
				"auth-client-default-scope": "user:full",
				"auth-client-id": "openshift-io",
				"auth-client-secret": "26c8c584-cbac-427d-8330-8b430b6ec620",
				"capacity-exhausted": false,
				"name": "starter-us-east-2a",
				"service-account-token": "eef1c5b8-f1f4-45dd-beef-7c34be5d9f9b",
				"service-account-username": "devtools-sre",
				"token-provider-id": "dd0ee660-3549-4617-9cab-6e679aab41e9"
			}
		]
	}`))
		log.Printf("[Cluster service] returning response with status: %d\n", http.StatusOK)
	}
}

func newWITServer() func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("[WIT service] incoming request: %s %s\n", r.Method, r.URL.Path)
		log.Printf("[WIT service] returning response with status: %d\n", http.StatusOK)
		rw.WriteHeader(http.StatusOK)
	}
}

func newTenantServer() func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("[Tenant service] incoming request: %s %s\n", r.Method, r.URL.Path)
		log.Printf("[Tenant service] returning response with status: %d\n", http.StatusNoContent)
		rw.WriteHeader(http.StatusNoContent)
	}
}

func newCheServer() func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("[Che service] incoming request: %s %s\n", r.Method, r.URL.Path)
		log.Printf("[Che service] returning response with status: %d\n", http.StatusNoContent)
		rw.WriteHeader(http.StatusNoContent)
	}
}

func displayAuthLogs(t *testing.T, output bytes.Buffer) {
	log.Println("***********************************************************")
	log.Println("-------------------- Auth Service Logs --------------------")
	log.Println("***********************************************************")
	log.Println(output.String())
	log.Println("***********************************************************")
}

func startServer(handler func(w http.ResponseWriter, r *http.Request), port int) (ts *httptest.Server) {
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "port=%d", port)
		}
	}
	if listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		panic(err)
	} else {
		ts = &httptest.Server{
			Listener: listener,
			Config:   &http.Server{Handler: http.HandlerFunc(handler)},
		}
		ts.Start()
	}
	return
}

func stopServer(server *httptest.Server) {
	if server != nil {
		server.Close()
	}
}

// helper

type Payload struct {
	Data *Data
}

type Data struct {
	Attributes *Attributes
}

type Attributes struct {
	ID string
}

func extractIDFromNotificationPayload(content []byte) string {
	var payload Payload
	err := json.Unmarshal([]byte(content), &payload)
	if err != nil {
		return ""
	}
	if payload.Data == nil {
		return ""
	}
	return payload.Data.Attributes.ID
}

func extractIDFromRegAppRequestPath(path string) string {
	// /api/namedusers/TestUserIdentity-1111/deprovision_osio 	// here `1111` is ID to be extracted
	startInd := strings.Index(path, "/TestUserIdentity-") + len("/TestUserIdentity-")
	endInd := strings.Index(path, "/deprovision_osio")
	return path[startInd:endInd]
}

func extractUsername(path string) string {
	startInd := strings.Index(path, "/api/accounts/") + len("/api/accounts/")
	endInd := strings.Index(path, "/deprovision_osio")
	return path[startInd:endInd]
}

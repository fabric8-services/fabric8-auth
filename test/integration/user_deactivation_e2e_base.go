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
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/fabric8-services/fabric8-auth/gormtestsupport"
	testsupport "github.com/fabric8-services/fabric8-auth/test"
	testtoken "github.com/fabric8-services/fabric8-auth/test/token"
)

var authBinary = "../../bin/auth"

var saToken string

var ago40days = time.Now().Add(-40 * 24 * time.Hour)
var ago7days = time.Now().Add(-7 * 24 * time.Hour)

type BaseSuite struct {
	gormtestsupport.DBTestSuite

	witServer          *httptest.Server
	notificationServer *httptest.Server
	tenantServer       *httptest.Server
	clusterServer      *httptest.Server
	cheServer          *httptest.Server
	regAppServer       *httptest.Server
}

func (s *BaseSuite) SetupSuite() {
	s.DBTestSuite.SetupSuite()

	saToken, _ = testtoken.TokenManager.GenerateServiceAccountToken(testsupport.TestOnlineRegistrationAppIdentity.ID.String(),
		testsupport.TestOnlineRegistrationAppIdentity.Username)
}

func (s *BaseSuite) SetupTest(NotificationDone, DeactivateDone chan string) {
	s.DBTestSuite.SetupTest()

	// start mock server
	s.witServer = startServer(8080, ServeWITRequests)
	s.notificationServer = startServer(8082, GetNotificationServer(NotificationDone))
	s.tenantServer = startServer(8090, ServeTenantRequests)
	s.clusterServer = startServer(8083, ServeClusterRequests)
	s.cheServer = startServer(8091, ServeCheRequests)
	s.regAppServer = startServer(8085, GetRegAppServer(DeactivateDone))
}

func (s *BaseSuite) TearDownTest() {
	s.DBTestSuite.TearDownTest()

	// stop mock server
	stopServer(s.witServer)
	stopServer(s.notificationServer)
	stopServer(s.tenantServer)
	stopServer(s.clusterServer)
	stopServer(s.cheServer)
	stopServer(s.regAppServer)
}

func (s *BaseSuite) cmdAuth(args ...string) (*exec.Cmd, *bytes.Buffer) {
	cmd := exec.Command(authBinary, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	return cmd, &out
}

func (s *BaseSuite) authCmd(args ...string) (*exec.Cmd, func(*testing.T)) {
	cmd, out := s.cmdAuth(args...)
	return cmd, func(t *testing.T) {
		displayAuthLogs(t, out)
	}
}

func GetRegAppServer(DeactivateDone chan string) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("RegApp service, Got Request, method:%s, path:%s\n", r.Method, r.URL.Path)

		username := extractUsername(r.URL.Path)
		url := fmt.Sprintf("http://127.0.0.1:8089/api/namedusers/%s/deactivate", username)
		req, _ := http.NewRequest(http.MethodPatch, url, nil)
		tokenHeader := fmt.Sprintf("Bearer %s", saToken)
		req.Header.Set("Authorization", tokenHeader)

		httpClient := http.Client{}
		res, err := httpClient.Do(req)
		if err != nil {
			log.Printf("RegApp service, failed, err:%v\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
			log.Printf("RegApp service, Return Response, status:%d\n", http.StatusInternalServerError)
			return
		}
		userID := extractIDFromRegAppRequestPath(r.URL.Path)
		DeactivateDone <- userID
		log.Printf("RegApp service, Return Response, status:%d\n", res.StatusCode)
	}
}

func GetNotificationServer(NotificationDone chan string) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("Notification service, Got Request, method:%s, path:%s\n", r.Method, r.URL.Path)

		defer r.Body.Close()
		content, _ := ioutil.ReadAll(r.Body)
		identityID := extractIDFromNotificationPayload(content)
		NotificationDone <- identityID

		rw.WriteHeader(http.StatusAccepted)
		log.Printf("Notification service, Return Response, status:%d\n", http.StatusAccepted)
	}
}

func ServeClusterRequests(rw http.ResponseWriter, r *http.Request) {
	log.Printf("Cluster service, Got Request, method:%s, path:%s\n", r.Method, r.URL.Path)
	rw.Write([]byte(`{
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
	log.Printf("Cluster service, Return Response, status:%d\n", http.StatusOK)
}

func ServeWITRequests(rw http.ResponseWriter, r *http.Request) {
	log.Printf("WIT service, Got Request, method:%s, path:%s\n", r.Method, r.URL.Path)
	log.Printf("WIT service, Return Response, status:%d\n", http.StatusOK)
}

func ServeTenantRequests(rw http.ResponseWriter, r *http.Request) {
	log.Printf("Tenant service, Got Request, method:%s, path:%s\n", r.Method, r.URL.Path)
	rw.WriteHeader(http.StatusNoContent)
	log.Printf("Tenant service, Return Response, status:%d\n", http.StatusNoContent)
}

func ServeCheRequests(rw http.ResponseWriter, r *http.Request) {
	log.Printf("Che service, Got Request, method:%s, path:%s\n", r.Method, r.URL.Path)
	log.Printf("Che service, Return Response, status:%d\n", http.StatusOK)
}

func displayAuthLogs(t *testing.T, output *bytes.Buffer) {
	log.Println("***********************************************************")
	log.Println("-------------------- Auth Servcie Logs --------------------")
	log.Println("***********************************************************")
	fmt.Print(output.String())
	log.Println("***********************************************************")
}

func startServer(port int, handler func(w http.ResponseWriter, r *http.Request)) (ts *httptest.Server) {
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
	json.Unmarshal([]byte(content), &payload)
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

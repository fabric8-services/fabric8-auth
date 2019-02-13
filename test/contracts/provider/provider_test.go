package provider_test

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pact-foundation/pact-go/dsl"
	"github.com/pact-foundation/pact-go/types"
)

// TestAuthAPIProvider verifies the provider
func TestAuthAPIProvider(t *testing.T) {

	var pactDir = os.Getenv("PACT_DIR")
	var pactProviderBaseURL = os.Getenv("PACT_PROVIDER_BASE_URL")

	var pactConsumer = os.Getenv("PACT_CONSUMER")
	var pactProvider = "fabric8-auth"

	var pactVersion = os.Getenv("PACT_VERSION")

	var pactBrokerUsername = os.Getenv("PACT_BROKER_USERNAME")
	var pactBrokerPassword = os.Getenv("PACT_BROKER_PASSWORD")
	var pactBrokerURL = os.Getenv("PACT_BROKER_URL")

	var userName = os.Getenv("OSIO_USERNAME")
	var userPassword = os.Getenv("OSIO_PASSWORD")
	var userCluster = os.Getenv("OSIO_CLUSTER_URL")

	/*
		log.Printf("pactDir=%s\n", pactDir)
		log.Printf("pactProviderBaseURL=%s\n", pactProviderBaseURL)
		log.Printf("pactConsumer=%s\n", pactConsumer)
		log.Printf("pactProvider=%s\n", pactProvider)
		log.Printf("pactVersion=%s\n", pactVersion)
		log.Printf("pactBrokerUsername=%s\n", pactBrokerUsername)
		log.Printf("pactBrokerPassword=%s\n", pactBrokerPassword)
		log.Printf("pactBrokerURL=%s\n", pactBrokerURL)
		log.Printf("userName=%s\n", userName)
		log.Printf("userPassword=%s\n", userPassword)
		/*/
	//*/

	// Create Pact connecting to local Daemon
	pact := &dsl.Pact{
		Consumer:             pactConsumer,
		Provider:             pactProvider,
		PactDir:              pactDir,
		Host:                 "localhost",
		LogDir:               pactDir,
		LogLevel:             "INFO",
		SpecificationVersion: 2,
	}
	defer pact.Teardown()

	var providerSetupHost = "localhost" // this should ultimately be part of the provider api (developer mode: on)
	var providerSetupPort = 8080

	// Set provider into initial state
	providerInfo := Setup(providerSetupHost, providerSetupPort, pactProviderBaseURL, userName, userPassword, userCluster)

	if providerInfo == nil {
		log.Fatalf("Unable to setup provider initial state")
	}
	var pactContent string
	var err error

	if pactBrokerURL != "" {
		// Download pact file from pact broker
		log.Printf("Downloading pact from a broker: %s", pactBrokerURL)
		pactContent, err = pactFromBroker(
			pactBrokerURL, pactBrokerUsername, pactBrokerPassword,
			pactConsumer, pactProvider, pactVersion,
		)
		if err != nil {
			log.Fatalf("Unable to download pact from broker: %q", err)
		}
	} else {
		// Load a pact file cached locally
		pactFile := fmt.Sprintf("%s/%s-%s.json", pactDir, strings.ToLower(pactConsumer), strings.ToLower(pactProvider))
		log.Printf("Loading a pact file from file: %s", pactFile)
		pactContent = pactFromFile(pactFile)
	}

	// Replace placeholders in pact file with real data (user name/id/token)
	pactContent = strings.Replace(pactContent, TestUserName, providerInfo.User.Data.Attributes.Username, -1)
	pactContent = strings.Replace(pactContent, TestUserID, providerInfo.User.Data.ID, -1)
	pactContent = strings.Replace(pactContent, TestJWSToken, providerInfo.Tokens.AccessToken, -1)

	err = os.MkdirAll(pactDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Unable to create a pact directory (%s): %q", pactDir, err)
	}

	pactFilePath := fmt.Sprintf("%s/provider-%s-%s.json", pactDir, strings.ToLower(pactConsumer), strings.ToLower(pactProvider))
	pactFile, err := os.Create(pactFilePath)
	if err != nil {
		log.Fatalf("Unable to create a local pact file (%s): %q", pactFilePath, err)
	}
	defer pactFile.Close()

	_, err = pactFile.WriteString(pactContent)
	if err != nil {
		log.Fatalf("Unable to write into pact file (%s): %q", pactFilePath, err)
	}

	// Verify the Provider with local Pact Files
	_, err = pact.VerifyProvider(t, types.VerifyRequest{
		ProviderBaseURL:        pactProviderBaseURL,
		PactURLs:               []string{pactFilePath},
		ProviderStatesSetupURL: fmt.Sprintf("http://%s:%d/pact/setup", providerSetupHost, providerSetupPort),
	})
	if err != nil {
		log.Fatalf("Unable to verify provider: %q", err)
	}

	log.Println("Test Passed!")
}

// pactFromFile reads a pact from a given file and returns as string
func pactFromFile(pactFile string) string {
	f, err := ioutil.ReadFile(pactFile)
	if err != nil {
		log.Fatalf("Unable to read pact file: %s", pactFile)
	}
	return string(f)
}

// pactFromBroker reads a pact from a given pact broker and returns as string
func pactFromBroker(pactBrokerURL string, pactBrokerUsername string, pactBrokerPassword string, pactConsumer string, pactProvider string, pactVersion string) (string, error) {

	var httpClient = &http.Client{
		Timeout: time.Second * 30,
	}
	var pactURL string
	if pactVersion == "latest" {
		pactURL = fmt.Sprintf("%s/pacts/provider/%s/consumer/%s/latest", pactBrokerURL, pactProvider, pactConsumer)
	} else {
		pactURL = fmt.Sprintf("%s/pacts/provider/%s/consumer/%s/version/%s", pactBrokerURL, pactProvider, pactConsumer, pactVersion)
	}
	request, err := http.NewRequest("GET", pactURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", pactBrokerUsername, pactBrokerPassword)))))

	log.Printf("Downloading a pact file from pact broker: %s", pactURL)
	response, err := httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", fmt.Errorf("Unexpected response code while downloading a pact file: %d", response.StatusCode)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("Unable to read HTTP response from pact broker:\n%q", err)
		return "", err
	}

	// Replace placeholders in pact file with real data (user name/id/token)
	return string(responseBody), nil
}

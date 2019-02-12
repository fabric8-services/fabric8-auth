package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/pmacik/loginusers-go/config"
	"github.com/pmacik/loginusers-go/loginusers"

	"github.com/fabric8-services/fabric8-auth/test/contracts/model"
)

type providerStateInfo struct {
	// Consumer name
	Consumer string `json:"consumer"`
	// State
	State string `json:"state"`
	// States
	States []string `json:"states"`
}

type ProviderInitialState struct {
	User   model.User
	Tokens loginusers.Tokens
}

type createUserAttributes struct {
	Bio       string `json:"bio"`
	Cluster   string `json:"cluster"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	RhdUserID string `json:"rhd_user_id"`
}

type createUserData struct {
	createUserAttributes `json:"attributes"`
	Type                 string `json:"type" pact:"example=identities"`
}

type createUserRequest struct {
	createUserData `json:"data"`
}

// Setup starts a setup service for a provider - should be replaced by a provider setup endpoint
func Setup(setupHost string, setupPort int, providerBaseURL string, userName string, userPassword string, userCluster string) *ProviderInitialState {
	log.SetOutput(os.Stdout)

	// Create test user in Auth and retun user info (such as id)
	log.Printf("Making sure user %s is created for cluster (%s)...", userName, userCluster)
	var user = ensureUser(providerBaseURL, userName, userCluster)
	if user == nil {
		log.Fatalf("Unable to create/get user")
	}
	log.Printf("Provider setup with user ID: %s", user.Data.ID)

	loginUsersConfig := config.DefaultConfig()
	loginUsersConfig.Auth.ServerAddress = providerBaseURL
	// Log user in to get tokens
	userTokens, err := loginusers.OAuth2(userName, userPassword, loginUsersConfig)
	if err != nil {
		log.Fatalf("Unable to login user: %s", err)
		return nil
	}

	go setupEndpoint(setupHost, setupPort)

	return &ProviderInitialState{
		User:   *user,
		Tokens: *userTokens,
	}
}

func setupEndpoint(setupHost string, setupPort int) {
	http.HandleFunc("/pact/setup", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatalf(">>> ERROR: Unable to read request body.\n %q", err)
			return
		}

		var providerState providerStateInfo
		err = json.Unmarshal(body, &providerState)
		if err != nil {
			log.Fatalf(">>> ERROR: Unable to unmarshall request body.\n %q", err)
			return
		}

		switch providerState.State {
		case "User with a given username exists.",
			"User with a given ID exists.",
			"A user exists with the given valid token.",
			"No user exists with the given token valid.",
			"Any user exists but no auth token was provided.",
			"Auth service is up and running.":
			log.Printf(">>>> %s\n", providerState.State)
		default:
			errorMessage(w, fmt.Sprintf("State '%s' not impemented.", providerState.State))
			return
		}
		fmt.Fprintf(w, "Provider states has ben set up.\n")
	})

	var setupURL = fmt.Sprintf("%s:%d", setupHost, setupPort)
	log.Printf(">>> Starting ProviderSetup and listening at %s\n", setupURL)
	log.Fatal(http.ListenAndServe(setupURL, nil))
}

func errorMessage(w http.ResponseWriter, errorMessage string) {
	w.WriteHeader(500)
	fmt.Fprintf(w, `{"error": "%s"}`, errorMessage)
}

func ensureUser(providerBaseURL string, userName string, userCluster string) *model.User {

	var httpClient = &http.Client{
		Timeout: time.Second * 10,
	}

	log.Println("Getting the auth service account token")
	authServiceAccountToken := serviceAccountToken(providerBaseURL)

	rhdUserUUID, _ := uuid.NewUUID()
	message := &createUserRequest{
		createUserData: createUserData{
			createUserAttributes: createUserAttributes{
				Bio:       "Contract testing user account",
				Cluster:   userCluster,
				Email:     fmt.Sprintf("%s@redhat.com", userName),
				Username:  userName,
				RhdUserID: rhdUserUUID.String(),
			},
			Type: "identities",
		},
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		log.Fatalf("createUser: Unable to marshal JSON object:\n%q", err)
	}

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/api/users", providerBaseURL), bytes.NewBuffer(messageBytes))
	if err != nil {
		log.Fatalf("createUser: Unable to create HTTP request:\n%q", err)
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authServiceAccountToken))

	log.Println("Sending a request to create a user")
	response, err := httpClient.Do(request)
	if err != nil {
		log.Fatalf("createUser: Unable to send HTTP request:\n%q", err)
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("createUser: Unable to read HTTP response:\n%q", err)
	}

	if response.StatusCode != 200 {
		if response.StatusCode == 409 { //user already exists
			log.Printf("User %s already exists, getting user info.", userName)
			response2, err := http.Get(fmt.Sprintf("%s/api/users?filter[username]=%s", providerBaseURL, userName))
			if err != nil {
				log.Fatalf("userExists: Unable to create HTTP request:\n%q", err)
			}
			defer response2.Body.Close()

			responseBody, err := ioutil.ReadAll(response2.Body)
			// log.Printf("User info:\n%s\n", responseBody)
			if err != nil {
				log.Fatalf("userExists: Error reading HTTP response:\n%q", err)
			}
			if response2.StatusCode != 200 {
				log.Fatalf("userExists: Something went wrong: %s", responseBody)
			}
			var users model.Users
			err = json.Unmarshal(responseBody, &users)
			if err != nil {
				log.Fatalf("userExists: Unable to unmarshal response body: %s", err)
			}
			var user = &model.User{
				Data: users.Data[0],
			}
			log.Printf("User found with ID: %s", user.Data.ID)
			return user
		}
		log.Fatalf("createUser: Something went wrong with reading response body: %s", responseBody)
	}

	var user model.User
	err = json.Unmarshal(responseBody, &user)
	if err != nil {
		log.Fatalf("createUser: Unable to unmarshal response body: %s", err)
	}
	log.Printf("User created with ID: %s", user.Data.ID)
	return &user
}

// ServiceAccountTokenRequest represents a request JSON body
type ServiceAccountTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// ServiceAccountTokenResponse represents a response JSON body
type ServiceAccountTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func serviceAccountToken(providerBaseURL string) string {
	var httpClient = &http.Client{
		Timeout: time.Second * 10,
	}
	authClientID := os.Getenv("AUTH_SERVICE_ACCOUNT_CLIENT_ID")
	authClienSecret := os.Getenv("AUTH_SERVICE_ACCOUNT_CLIENT_SECRET")

	message, err := json.Marshal(&ServiceAccountTokenRequest{
		GrantType:    "client_credentials",
		ClientID:     authClientID,
		ClientSecret: authClienSecret,
	})

	// log.Printf("Message: %s", string(message))

	if err != nil {
		log.Fatalf("serviceAccountToken: Unable to marshal JSON object: %q\n", err)
	}
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/api/token", providerBaseURL), bytes.NewBuffer(message))
	request.Header.Add("Content-Type", "application/json")
	if err != nil {
		log.Fatalf("serviceAccountToken: Unable to create HTTP request: %q\n", err)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		log.Fatalf("serviceAccountToken: Unable to send HTTP request: %q\n", err)
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("serviceAccountToken: Unable to read HTTP response:\n%q", err)
	}

	if response.StatusCode != 200 {
		log.Fatalf("serviceAccountToken: Something went wrong with reading response body: %s", responseBody)
	}

	var tokenResponse ServiceAccountTokenResponse
	err = json.Unmarshal(responseBody, &tokenResponse)
	if err != nil {
		log.Fatalf("serviceAccountToken: Unable to unmarshal response body: %s", err)
	}
	return tokenResponse.AccessToken
}

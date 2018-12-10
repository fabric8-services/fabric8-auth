package provider

const (
	ImageURLAttributeName = "imageURL"
	BioAttributeName      = "bio"
	URLAttributeName      = "url"
	CompanyAttributeName  = "company"
	ApprovedAttributeName = "approved"
	ClusterAttribute      = "cluster"
	RHDUsernameAttribute  = "rhd_username"
)

// OAuthUserProfile represents standard OAuth User profile api request payload
type OAuthUserProfile struct {
	ID            *string                     `json:"id,omitempty"`
	CreatedAt     int64                       `json:"createdTimestamp,omitempty"`
	Username      *string                     `json:"username,omitempty"`
	FirstName     *string                     `json:"firstName,omitempty"`
	LastName      *string                     `json:"lastName,omitempty"`
	Email         *string                     `json:"email,omitempty"`
	EmailVerified *bool                       `json:"emailVerified"`
	Attributes    *OAuthUserProfileAttributes `json:"attributes,omitempty"`
}

// OAuthUserProfileAttributes represents standard OAuth profile payload Attributes
type OAuthUserProfileAttributes map[string][]string

//OAuthUserProfileResponse represents the user profile api response from an oauth provider
type OAuthUserProfileResponse struct {
	ID                         *string                     `json:"id"`
	CreatedTimestamp           *int64                      `json:"createdTimestamp"`
	Username                   *string                     `json:"username"`
	Enabled                    *bool                       `json:"enabled"`
	Totp                       *bool                       `json:"totp"`
	EmailVerified              *bool                       `json:"emailVerified"`
	FirstName                  *string                     `json:"firstName"`
	LastName                   *string                     `json:"lastName"`
	Email                      *string                     `json:"email"`
	Attributes                 *OAuthUserProfileAttributes `json:"attributes"`
	DisableableCredentialTypes []*string                   `json:"disableableCredentialTypes"`
	RequiredActions            []interface{}               `json:"requiredActions"`
}

/*
{"username":"<USERNAME>","enabled":true,"emailVerified":true,
	"firstName":"<FIRST_NAME>","lastName":"<LAST_NAME>",
	"email":"<EMAIL>","attributes":{"approved":["true"],
		"rhd_username":["<USERNAME>"],"company":["<company claim from RHD token>"]}}
*/
type OAuthUserRequest struct {
	Username      *string                     `json:"username"`
	Enabled       *bool                       `json:"enabled"`
	EmailVerified *bool                       `json:"emailVerified"`
	FirstName     *string                     `json:"firstName"`
	LastName      *string                     `json:"lastName"`
	Email         *string                     `json:"email"`
	Attributes    *OAuthUserProfileAttributes `json:"attributes"`
}

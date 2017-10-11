package provider

import (
	"fmt"
	"strings"

	"github.com/fabric8-services/fabric8-auth/errors"
	uuid "github.com/satori/go.uuid"
)

// ExternalProvider defines the properties of an external provider
type ExternalProvider struct {
	ID           uuid.UUID
	URL          string
	Type         string
	DefaultScope string
}

// GithubProvider is a representation of the Github external provider.
var GithubProvider = ExternalProvider{
	ID:           uuid.FromStringOrNil("2f6b7176-8f4b-4204-962d-606033275397"),
	URL:          "github.com",
	Type:         "github",
	DefaultScope: "user:full", // TODO: move this out to constants.
}

// OpenShiftv3Provider is a respresentation of the OpenShiftv3 provider.
var OpenShiftv3Provider = ExternalProvider{
	ID:           uuid.FromStringOrNil("f867ac10-5e05-4359-a0c6-b855ece59090"),
	URL:          "openshift.com",
	Type:         "openshift-v3",
	DefaultScope: "admin:repo_hook read:org repo user gist", // TODO: move this out to constants.
}

// GetExternalProvider computes the external provider type from the resource url.
func GetExternalProvider(resource string) (*ExternalProvider, error) {

	// TODO: Add a proper regex URL check.
	if strings.Contains(resource, "github.com") {
		fmt.Println("found github.com")
		return &GithubProvider, nil
	} else if strings.Contains(resource, "openshift-v3") {
		return &OpenShiftv3Provider, nil
	}
	return nil, errors.NewBadParameterError("resource", resource).Expected("github or openshift url")
}

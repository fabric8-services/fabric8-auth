package provider

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestGitHubProviderID(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	_, err := uuid.FromString(GitHubProviderID)
	assert.Nil(t, err)
	assert.Equal(t, "2f6b7176-8f4b-4204-962d-606033275397", GitHubProviderID)
}

package link

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestOpenShiftProviderID(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	_, err := uuid.FromString(osoStarterEast2ProviderID)
	assert.Nil(t, err)
	assert.Equal(t, "f867ac10-5e05-4359-a0c6-b855ece59090", osoStarterEast2ProviderID)
}

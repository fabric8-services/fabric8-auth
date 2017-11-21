package link

import (
	"testing"

	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/stretchr/testify/require"
)

func TestOpenShiftProviderID(t *testing.T) {
	t.Parallel()
	resource.Require(t, resource.UnitTest)
	config, err := configuration.GetConfigurationData()
	require.Nil(t, err)

	cluster := config.GetOSOClusters()["https://api.starter-us-east-2.openshift.com"]
	_, err = NewOpenShiftConfig(cluster, "")
	require.Nil(t, err)
}

package suite

import (
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/stretchr/testify/suite"
)

// NewRemoteTestSuite instanciate a new RemoteTestSuite
func NewRemoteTestSuite() RemoteTestSuite {
	return RemoteTestSuite{}
}

// RemoteTestSuite is a base for tests using a gorm Remote
type RemoteTestSuite struct {
	suite.Suite
	Config *configuration.ConfigurationData
}

// SetupSuite implements suite.SetupAllSuite
func (s *RemoteTestSuite) SetupSuite() {
	resource.Require(s.T(), resource.Remote)
	config, err := configuration.GetConfigurationData()
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed to setup the configuration")
	}
	s.Config = config
}

// TearDownSuite implements suite.TearDownAllSuite
func (s *RemoteTestSuite) TearDownSuite() {
	s.Config = nil // Summon the GC!
}

package suite

import (
	"github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/resource"

	"github.com/stretchr/testify/suite"
)

// NewRemoteTestSuite instanciate a new UnitTestSuite
func NewUnitTestSuite() UnitTestSuite {
	return UnitTestSuite{}
}

// RemoteTestSuite is a base for unit tests
type UnitTestSuite struct {
	suite.Suite
	Config *configuration.ConfigurationData
}

// SetupSuite implements suite.SetupAllSuite
func (s *UnitTestSuite) SetupSuite() {
	resource.Require(s.T(), s.testType())
	config, err := configuration.GetConfigurationData()
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed to setup the configuration")
	}
	s.Config = config
}

func (s *UnitTestSuite) testType() string {
	return resource.UnitTest
}

// TearDownSuite implements suite.TearDownAllSuite
func (s *UnitTestSuite) TearDownSuite() {
	s.Config = nil // Summon the GC!
}

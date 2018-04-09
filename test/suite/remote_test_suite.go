package suite

import (
	"github.com/fabric8-services/fabric8-auth/resource"
)

// NewRemoteTestSuite instantiates a new RemoteTestSuite
func NewRemoteTestSuite() RemoteTestSuite {
	return RemoteTestSuite{}
}

// RemoteTestSuite is a base for tests which call remote services
type RemoteTestSuite struct {
	UnitTestSuite
}

// SetupSuite implements suite.SetupAllSuite
func (s *RemoteTestSuite) SetupSuite() {
	resource.Require(s.T(), resource.Remote)
	s.setupConfig()
}

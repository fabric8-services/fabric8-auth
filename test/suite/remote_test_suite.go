package suite

import (
	"github.com/fabric8-services/fabric8-auth/resource"
)

// NewRemoteTestSuite instanciate a new RemoteTestSuite
func NewRemoteTestSuite() RemoteTestSuite {
	return RemoteTestSuite{}
}

// RemoteTestSuite is a base for tests which call remote services
type RemoteTestSuite struct {
	UnitTestSuite
}

func (s *RemoteTestSuite) testType() string {
	return resource.Remote
}

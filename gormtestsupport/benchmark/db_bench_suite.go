package benchmark

import (
	"os"

	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/resource"
	"github.com/fabric8-services/fabric8-auth/test"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq" // need to import postgres driver
)

var _ test.SetupAllSuite = &DBBenchSuite{}
var _ test.TearDownAllSuite = &DBBenchSuite{}

// NewDBBenchSuite instanciate a new DBBenchSuite
func NewDBBenchSuite(configFilePath string) DBBenchSuite {
	return DBBenchSuite{configFile: configFilePath}
}

// DBBenchSuite is a base for tests using a gorm db
type DBBenchSuite struct {
	test.Suite
	configFile    string
	Configuration *config.ConfigurationData
	DB            *gorm.DB
}

// SetupSuite implements suite.SetupAllSuite
func (s *DBBenchSuite) SetupSuite() {
	resource.Require(s.B(), resource.Database)
	configuration, err := config.NewConfigurationData(s.configFile, "", "")
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed to setup the configuration")
	}
	s.Configuration = configuration
	if _, c := os.LookupEnv(resource.Database); c != false {
		s.DB, err = gorm.Open("postgres", s.Configuration.GetPostgresConfigString())
		if err != nil {
			log.Panic(nil, map[string]interface{}{
				"err":             err,
				"postgres_config": configuration.GetPostgresConfigString(),
			}, "failed to connect to the database")
		}
	}
}

// TearDownSuite implements suite.TearDownAllSuite
func (s *DBBenchSuite) TearDownSuite() {
	s.DB.Close()
}

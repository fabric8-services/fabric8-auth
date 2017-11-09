package main

import (
	"flag"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/fabric8-services/fabric8-auth/token/keycloak"

	"github.com/fabric8-services/fabric8-auth/account"
	"github.com/fabric8-services/fabric8-auth/app"
	"github.com/fabric8-services/fabric8-auth/application"
	"github.com/fabric8-services/fabric8-auth/auth"
	config "github.com/fabric8-services/fabric8-auth/configuration"
	"github.com/fabric8-services/fabric8-auth/controller"
	"github.com/fabric8-services/fabric8-auth/gormapplication"
	"github.com/fabric8-services/fabric8-auth/jsonapi"
	"github.com/fabric8-services/fabric8-auth/log"
	"github.com/fabric8-services/fabric8-auth/login"
	"github.com/fabric8-services/fabric8-auth/migration"
	"github.com/fabric8-services/fabric8-auth/space/authz"
	"github.com/fabric8-services/fabric8-auth/token"
	"github.com/fabric8-services/fabric8-auth/token/link"

	"github.com/goadesign/goa"
	"github.com/goadesign/goa/logging/logrus"
	"github.com/goadesign/goa/middleware"
	"github.com/goadesign/goa/middleware/gzip"
	"github.com/goadesign/goa/middleware/security/jwt"
	"github.com/jinzhu/gorm"
)

func main() {
	// --------------------------------------------------------------------
	// Parse flags
	// --------------------------------------------------------------------
	var configFile string
	var serviceAccountConfigFile string
	var printConfig bool
	var migrateDB bool
	flag.StringVar(&configFile, "config", "", "Path to the config file to read")
	flag.StringVar(&serviceAccountConfigFile, "serviceAccountConfig", "", "Path to the service account configuration file")
	flag.BoolVar(&printConfig, "printConfig", false, "Prints the config (including merged environment variables) and exits")
	flag.BoolVar(&migrateDB, "migrateDatabase", false, "Migrates the database to the newest version and exits.")
	flag.Parse()

	// Override default -config switch with environment variable only if -config switch was
	// not explicitly given via the command line.
	configSwitchIsSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			configSwitchIsSet = true
		}
	})
	if !configSwitchIsSet {
		if envConfigPath, ok := os.LookupEnv("AUTH_CONFIG_FILE_PATH"); ok {
			configFile = envConfigPath
		}
	}

	serviceAccountConfigSwitchIsSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "serviceAccountConfig" {
			serviceAccountConfigSwitchIsSet = true
		}
	})
	if !serviceAccountConfigSwitchIsSet {
		if envServiceAccountConfig, ok := os.LookupEnv("AUTH_SERVICE_ACCOUNT_CONFIG_FILE"); ok {
			serviceAccountConfigFile = envServiceAccountConfig
		}
	}

	configuration, err := config.NewConfigurationData(configFile, serviceAccountConfigFile)
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"config_file":                 configFile,
			"service_account_config_file": serviceAccountConfigFile,
			"err": err,
		}, "failed to setup the configuration")
	}

	if printConfig {
		os.Exit(0)
	}

	// Initialized developer mode flag and log level for the logger
	log.InitializeLogger(configuration.IsLogJSON(), configuration.GetLogLevel())

	printUserInfo()

	var db *gorm.DB
	for {
		db, err = gorm.Open("postgres", configuration.GetPostgresConfigString())
		if err != nil {
			db.Close()
			log.Logger().Errorf("ERROR: Unable to open connection to database %v", err)
			log.Logger().Infof("Retrying to connect in %v...", configuration.GetPostgresConnectionRetrySleep())
			time.Sleep(configuration.GetPostgresConnectionRetrySleep())
		} else {
			defer db.Close()
			break
		}
	}

	if configuration.IsPostgresDeveloperModeEnabled() && log.IsDebug() {
		db = db.Debug()
	}

	if configuration.GetPostgresConnectionMaxIdle() > 0 {
		log.Logger().Infof("Configured connection pool max idle %v", configuration.GetPostgresConnectionMaxIdle())
		db.DB().SetMaxIdleConns(configuration.GetPostgresConnectionMaxIdle())
	}
	if configuration.GetPostgresConnectionMaxOpen() > 0 {
		log.Logger().Infof("Configured connection pool max open %v", configuration.GetPostgresConnectionMaxOpen())
		db.DB().SetMaxOpenConns(configuration.GetPostgresConnectionMaxOpen())
	}

	// Set the database transaction timeout
	application.SetDatabaseTransactionTimeout(configuration.GetPostgresTransactionTimeout())

	// Migrate the schema
	err = migration.Migrate(db.DB(), configuration.GetPostgresDatabase(), configuration)
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed migration")
	}

	// Nothing to here except exit, since the migration is already performed.
	if migrateDB {
		os.Exit(0)
	}

	// Load service accounts
	//	application.s

	// Create service
	service := goa.New("auth")

	// Mount middleware
	service.Use(middleware.RequestID())
	// Use our own log request to inject identity id and modify other properties
	service.Use(log.LogRequest(configuration.IsPostgresDeveloperModeEnabled()))
	service.Use(gzip.Middleware(9))
	service.Use(jsonapi.ErrorHandler(service, true))
	service.Use(middleware.Recover())

	service.WithLogger(goalogrus.New(log.Logger()))

	// Setup Account/Login/Security
	identityRepository := account.NewIdentityRepository(db)
	userRepository := account.NewUserRepository(db)

	appDB := gormapplication.NewGormDB(db)

	tokenManager, err := token.NewManager(configuration)
	if err != nil {
		log.Panic(nil, map[string]interface{}{
			"err": err,
		}, "failed to create token manager")
	}
	app.UseJWTMiddleware(service, jwt.New(tokenManager.PublicKeys(), nil, app.NewJWTSecurity()))
	service.Use(login.InjectTokenManager(tokenManager))
	spaceAuthzService := authz.NewAuthzService(configuration)
	service.Use(authz.InjectAuthzService(spaceAuthzService))

	// Mount "login" controller
	loginService := login.NewKeycloakOAuthProvider(identityRepository, userRepository, tokenManager, appDB)
	loginCtrl := controller.NewLoginController(service, loginService, tokenManager, configuration)
	app.MountLoginController(service, loginCtrl)

	// Mount "logout" controller
	logoutCtrl := controller.NewLogoutController(service, &login.KeycloakLogoutService{}, configuration)
	app.MountLogoutController(service, logoutCtrl)

	providerFactory := link.NewOauthProviderFactory(configuration)
	linkService := link.NewLinkServiceWithFactory(configuration, appDB, providerFactory)
	//providerFactory := link.NewOauthProviderFactory(configuration, appDB)
	keycloakExternalTokenService := keycloak.NewKeycloakTokenServiceClient()
	// Mount "token" controller
	tokenCtrl := controller.NewTokenController(service, appDB, loginService, linkService, providerFactory, tokenManager, &keycloakExternalTokenService, configuration)
	app.MountTokenController(service, tokenCtrl)

	// Mount "link" controller
	linkCtrl := controller.NewLinkController(service, loginService, tokenManager, configuration)
	app.MountLinkController(service, linkCtrl)

	// Mount "status" controller
	statusCtrl := controller.NewStatusController(service, db)
	app.MountStatusController(service, statusCtrl)

	// Mount "space" controller
	spaceCtrl := controller.NewSpaceController(service, appDB, configuration, auth.NewKeycloakResourceManager(configuration))
	app.MountSpaceController(service, spaceCtrl)

	// Mount "user" controller
	userCtrl := controller.NewUserController(service, appDB, tokenManager, configuration)
	app.MountUserController(service, userCtrl)

	// Mount "search" controller
	searchCtrl := controller.NewSearchController(service, appDB, configuration)
	app.MountSearchController(service, searchCtrl)

	// Mount "users" controller
	keycloakProfileService := login.NewKeycloakUserProfileClient()
	usersCtrl := controller.NewUsersController(service, appDB, configuration, keycloakProfileService)
	app.MountUsersController(service, usersCtrl)

	// Mount "collaborators" controller
	collaboratorsCtrl := controller.NewCollaboratorsController(service, appDB, configuration, auth.NewKeycloakPolicyManager(configuration))
	app.MountCollaboratorsController(service, collaboratorsCtrl)

	log.Logger().Infoln("Git Commit SHA: ", controller.Commit)
	log.Logger().Infoln("UTC Build Time: ", controller.BuildTime)
	log.Logger().Infoln("UTC Start Time: ", controller.StartTime)
	log.Logger().Infoln("Dev mode:       ", configuration.IsPostgresDeveloperModeEnabled())
	log.Logger().Infoln("GOMAXPROCS:     ", runtime.GOMAXPROCS(-1))
	log.Logger().Infoln("NumCPU:         ", runtime.NumCPU())

	http.Handle("/api/", service.Mux)
	http.Handle("/", http.FileServer(assetFS()))
	http.Handle("/favicon.ico", http.NotFoundHandler())

	// Start http
	if err := http.ListenAndServe(configuration.GetHTTPAddress(), nil); err != nil {
		log.Error(nil, map[string]interface{}{
			"addr": configuration.GetHTTPAddress(),
			"err":  err,
		}, "unable to connect to server")
		service.LogError("startup", "err", err)
	}
}

func printUserInfo() {
	u, err := user.Current()
	if err != nil {
		log.Warn(nil, map[string]interface{}{
			"err": err,
		}, "failed to get current user")
	} else {
		log.Info(nil, map[string]interface{}{
			"username": u.Username,
			"uuid":     u.Uid,
		}, "Running as user name '%s' with UID %s.", u.Username, u.Uid)
		g, err := user.LookupGroupId(u.Gid)
		if err != nil {
			log.Warn(nil, map[string]interface{}{
				"err": err,
			}, "failed to lookup group")
		} else {
			log.Info(nil, map[string]interface{}{
				"groupname": g.Name,
				"gid":       g.Gid,
			}, "Running as as group '%s' with GID %s.", g.Name, g.Gid)
		}
	}
}

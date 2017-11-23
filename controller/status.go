package controller

import (
	"time"

	"github.com/fabric8-services/fabric8-auth/app"

	"github.com/goadesign/goa"
	"github.com/jinzhu/gorm"
)

var (
	// Commit current build commit set by build script
	Commit = "0"
	// BuildTime set by build script in ISO 8601 (UTC) format: YYYY-MM-DDThh:mm:ssTZD (see https://www.w3.org/TR/NOTE-datetime for details)
	BuildTime = "0"
	// StartTime in ISO 8601 (UTC) format
	StartTime = time.Now().UTC().Format("2006-01-02T15:04:05Z")
)

type statusConfiguration interface {
	IsPostgresDeveloperModeEnabled() bool
	DefaultConfigurationError() error
}

// DBChecker is to be used to check if the DB is reachable
type DBChecker interface {
	Ping() error
}

// StatusController implements the status resource.
type StatusController struct {
	*goa.Controller
	dbChecker DBChecker
	config    statusConfiguration
}

// NewStatusController creates a status controller.
func NewStatusController(service *goa.Service, dbChecker DBChecker, config statusConfiguration) *StatusController {
	return &StatusController{
		Controller: service.NewController("StatusController"),
		dbChecker:  dbChecker,
		config:     config,
	}
}

// Show runs the show action.
func (c *StatusController) Show(ctx *app.ShowStatusContext) error {
	res := &app.Status{
		Commit:    Commit,
		BuildTime: BuildTime,
		StartTime: StartTime,
	}

	devMode := c.config.IsPostgresDeveloperModeEnabled()
	if devMode {
		res.DevMode = &devMode
	}

	err := c.dbChecker.Ping()
	if err != nil {
		message := err.Error()
		res.Error = &message
		return ctx.ServiceUnavailable(res)
	}

	err = c.config.DefaultConfigurationError()
	if err != nil {
		message := err.Error()
		res.Error = &message
		if !devMode {
			return ctx.ServiceUnavailable(res)
		}
	}

	return ctx.OK(res)
}

// GormDBChecker implements DB checker
type GormDBChecker struct {
	db *gorm.DB
}

// NewGormDBChecker constructs a new GormDBChecker
func NewGormDBChecker(db *gorm.DB) DBChecker {
	return &GormDBChecker{
		db: db,
	}
}

func (c *GormDBChecker) Ping() error {
	_, err := c.db.DB().Exec("select 1")
	return err
}

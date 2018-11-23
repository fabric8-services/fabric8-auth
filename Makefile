PROJECT_NAME=fabric8-auth
CUR_DIR=$(shell pwd)
TMP_PATH=$(CUR_DIR)/tmp
INSTALL_PREFIX=$(CUR_DIR)/bin
VENDOR_DIR=vendor
ifeq ($(OS),Windows_NT)
include ./.make/Makefile.win
else
include ./.make/Makefile.lnx
endif
SOURCE_DIR ?= .
SOURCES := $(shell find $(SOURCE_DIR) -path $(SOURCE_DIR)/vendor -prune -o -name '*.go' -print)
DESIGN_DIR=design
DESIGNS := $(shell find $(SOURCE_DIR)/$(DESIGN_DIR) -path $(SOURCE_DIR)/vendor -prune -o -name '*.go' -print)
DOCS_DIR=docs
DOCS_SOURCE_DIR=$(DOCS_DIR)/source

# Find all required tools:
GIT_BIN := $(shell command -v $(GIT_BIN_NAME) 2> /dev/null)
DEP_BIN_NAME := dep
DEP_BIN_DIR := ./tmp/bin
DEP_BIN := $(DEP_BIN_DIR)/$(DEP_BIN_NAME)
DEP_VERSION=v0.4.1
GO_BIN := $(shell command -v $(GO_BIN_NAME) 2> /dev/null)
MINIMOCK_BIN=$(VENDOR_DIR)/github.com/gojuno/minimock/cmd/minimock/minimock
DOCKER_COMPOSE_BIN := $(shell command -v $(DOCKER_COMPOSE_BIN_NAME) 2> /dev/null)
DOCKER_BIN := $(shell command -v $(DOCKER_BIN_NAME) 2> /dev/null)
ASCIIDOCTOR_BIN := $(shell command -v $(ASCIIDOCTOR_BIN_NAME) 2> /dev/null)

# Define and get the vakue for UNAME_S variable from shell
UNAME_S := $(shell uname -s)

# This is a fix for a non-existing user in passwd file when running in a docker
# container and trying to clone repos of dependencies
GIT_COMMITTER_NAME ?= "user"
GIT_COMMITTER_EMAIL ?= "user@example.com"
export GIT_COMMITTER_NAME
export GIT_COMMITTER_EMAIL

# Used as target and binary output names... defined in includes
CLIENT_DIR=tool/auth-cli

COMMIT=$(shell git rev-parse HEAD)
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
COMMIT := $(COMMIT)-dirty
endif
BUILD_TIME=`date -u '+%Y-%m-%dT%H:%M:%SZ'`

PACKAGE_NAME := github.com/fabric8-services/fabric8-auth

# For the global "clean" target all targets in this variable will be executed
CLEAN_TARGETS =

# Pass in build time variables to main
LDFLAGS=-ldflags "-X ${PACKAGE_NAME}/controller.Commit=${COMMIT} -X ${PACKAGE_NAME}/controller.BuildTime=${BUILD_TIME}"

# Call this function with $(call log-info,"Your message")
define log-info =
@echo "INFO: $(1)"
endef

# If nothing was specified, run all targets as if in a fresh clone
.PHONY: all
## Default target - fetch dependencies, generate code and build.
all: prebuild-check deps generate build

.PHONY: help
# Based on https://gist.github.com/rcmachado/af3db315e31383502660
## Display this help text.
help:/
	$(info Available targets)
	$(info -----------------)
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		helpCommand = substr($$1, 0, index($$1, ":")-1); \
		if (helpMessage) { \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			gsub(/##/, "\n                                     ", helpMessage); \
		} else { \
			helpMessage = "(No documentation)"; \
		} \
		printf "%-35s - %s\n", helpCommand, helpMessage; \
		lastLine = "" \
	} \
	{ hasComment = match(lastLine, /^## (.*)/); \
          if(hasComment) { \
            lastLine=lastLine$$0; \
	  } \
          else { \
	    lastLine = $$0 \
          } \
        }' $(MAKEFILE_LIST)

GOFORMAT_FILES := $(shell find  . -name '*.go' | grep -vEf .gofmt_exclude)

.PHONY: check-go-format
## Exists with an error if there are files whose formatting differs from gofmt's
check-go-format: prebuild-check
	@gofmt -s -l ${GOFORMAT_FILES} 2>&1 \
		| tee /tmp/gofmt-errors \
		| read \
	&& echo "ERROR: These files differ from gofmt's style (run 'make format-go-code' to fix this):" \
	&& cat /tmp/gofmt-errors \
	&& exit 1 \
	|| true

.PHONY: install-git-hooks
## Creates useful git hooks (e.g. pre-push go-format-code check)
install-git-hooks:
	@ln -sfv ../../.pre-push .git/hooks/pre-push

CLEAN_TARGETS += clean-git-hooks
.PHONY: clean-git-hooks
## Removes hooks that have been installed with the "install-git-hooks" target
clean-git-hooks:
	@test "$(shell readlink -f .git/hooks/pre-push)" = "${CUR_DIR}/.pre-push" \
	&& rm -v .git/hooks/pre-push \
	|| true

.PHONY: release
release: prebuild-check deps generate build check-go-format test-unit-junit

.PHONY: analyze-go-code
## Run a complete static code analysis using the following tools: golint, gocyclo and go-vet.
analyze-go-code: golint gocyclo govet

## Run gocyclo analysis over the code.
golint: $(GOLINT_BIN)
	$(info >>--- RESULTS: GOLINT CODE ANALYSIS ---<<)
	@$(foreach d,$(GOANALYSIS_DIRS),$(GOLINT_BIN) $d 2>&1 | grep -vEf .golint_exclude || true;)

## Run gocyclo analysis over the code.
gocyclo: $(GOCYCLO_BIN)
	$(info >>--- RESULTS: GOCYCLO CODE ANALYSIS ---<<)
	@$(foreach d,$(GOANALYSIS_DIRS),$(GOCYCLO_BIN) -over 10 $d | grep -vEf .golint_exclude || true;)

## Run go vet analysis over the code.
govet:
	$(info >>--- RESULTS: GO VET CODE ANALYSIS ---<<)
	@$(foreach d,$(GOANALYSIS_DIRS),go tool vet --all $d/*.go 2>&1;)

.PHONY: format-go-code
## Formats any go file that differs from gofmt's style
format-go-code: prebuild-check
	@gofmt -s -l -w ${GOFORMAT_FILES}

$(MINIMOCK_BIN):
	@echo "building the minimock binary..."
	@cd $(VENDOR_DIR)/github.com/gojuno/minimock/cmd/minimock && go build -v minimock.go

.PHONY: generate-minimock
generate-minimock: deps $(MINIMOCK_BIN) ## Generate Minimock sources. Only necessary after clean or if changes occurred in interfaces.
	@echo "Generating mocks..."
	@-mkdir -p test/service
	@$(MINIMOCK_BIN) -i github.com/fabric8-services/fabric8-auth/application/service.NotificationService,github.com/fabric8-services/fabric8-auth/application/service.WITService,github.com/fabric8-services/fabric8-auth/application/service.ClusterService,github.com/fabric8-services/fabric8-auth/application/service.AuthenticationProviderService -o ./test/service/ -s ".go"
	@-mkdir -p test/token/oauth
	@$(MINIMOCK_BIN) -i github.com/fabric8-services/fabric8-auth/authentication/provider.IdentityProvider -o ./test/token/oauth/ -s ".go"
	@-mkdir -p test/generated/authorization/token/manager
	@$(MINIMOCK_BIN) -i github.com/fabric8-services/fabric8-auth/authorization/token/manager.TokenManagerConfiguration -o ./test/generated/authorization/token/manager/ -s ".go"
	@-mkdir -p test/generated/application/service
	@$(MINIMOCK_BIN) -i github.com/fabric8-services/fabric8-auth/application/service.AuthenticationProviderService -o ./test/generated/application/service/ -s ".go"

.PHONY: generate-client
generate-client: $(GOAGEN_BIN)
	$(GOAGEN_BIN) client -d github.com/fabric8-services/fabric8-auth/design --pkg auth

.PHONY: build
## Build server and client.
build: prebuild-check deps generate $(BINARY_SERVER_BIN) $(BINARY_CLIENT_BIN) # do the build

$(BINARY_SERVER_BIN): $(SOURCES)
ifeq ($(OS),Windows_NT)
	go build -v ${LDFLAGS} -o "$(shell cygpath --windows '$(BINARY_SERVER_BIN)')"
else
	go build -v ${LDFLAGS} -o ${BINARY_SERVER_BIN}
endif

$(BINARY_CLIENT_BIN): $(SOURCES)
ifeq ($(OS),Windows_NT)
	cd ${CLIENT_DIR}/ && go build -v ${LDFLAGS} -o "$(shell cygpath --windows '$(BINARY_CLIENT_BIN)')"
else
	cd ${CLIENT_DIR}/ && go build -v -o ${BINARY_CLIENT_BIN}
endif

# Build go tool to analysis the code
$(GOLINT_BIN):
	cd $(VENDOR_DIR)/github.com/golang/lint/golint && go build -v
$(GOCYCLO_BIN):
	cd $(VENDOR_DIR)/github.com/fzipp/gocyclo && go build -v

# Pack all migration SQL files into a compilable Go file
migration/sqlbindata.go: $(GO_BINDATA_BIN) $(wildcard migration/sql-files/*.sql) migration/sqlbindata_test.go
	$(GO_BINDATA_BIN) \
		-o migration/sqlbindata.go \
		-pkg migration \
		-prefix migration/sql-files \
		-nocompress \
		migration/sql-files

migration/sqlbindata_test.go: $(GO_BINDATA_BIN) $(wildcard migration/sql-test-files/*.sql)
	$(GO_BINDATA_BIN) \
		-o migration/sqlbindata_test.go \
		-pkg migration_test \
		-prefix migration/sql-test-files \
		-nocompress \
		migration/sql-test-files

# Pack configuration files into a compilable Go file
configuration/confbindata.go: $(GO_BINDATA_BIN) $(wildcard configuration/conf-files/*.conf)
	$(GO_BINDATA_BIN) \
		-o configuration/confbindata.go \
		-pkg configuration \
		-prefix configuration/conf-files \
		-nocompress \
		configuration/conf-files

# These are binary tools from our vendored packages
$(GOAGEN_BIN): $(VENDOR_DIR)
	cd $(VENDOR_DIR)/github.com/goadesign/goa/goagen && go build -v
$(GO_BINDATA_BIN): $(VENDOR_DIR)
	cd $(VENDOR_DIR)/github.com/jteeuwen/go-bindata/go-bindata && go build -v
$(FRESH_BIN): $(VENDOR_DIR)
	cd $(VENDOR_DIR)/github.com/pilu/fresh && go build -v
$(GO_JUNIT_BIN): $(VENDOR_DIR)
	cd $(VENDOR_DIR)/github.com/jstemmer/go-junit-report && go build -v

CLEAN_TARGETS += clean-artifacts
.PHONY: clean-artifacts
## Removes the ./bin directory.
clean-artifacts:
	-rm -rf $(INSTALL_PREFIX)

CLEAN_TARGETS += clean-object-files
.PHONY: clean-object-files
## Runs go clean to remove any executables or other object files.
clean-object-files:
	go clean ./...

CLEAN_TARGETS += clean-generated
.PHONY: clean-generated
## Removes all generated code.
clean-generated:
	-rm -rf ./app
	-rm -rf ./client/
	-rm -rf ./swagger/
	-rm -rf ./tool/cli/
	-rm -f ./migration/sqlbindata.go
	-rm -f ./migration/sqlbindata_test.go
	-rm -f ./configuration/confbindata.go
	-rm -rf wit/witservice
	-rm -rf ./authentication/account/tenant
	-rm -rf ./test/service
	-rm -rf ./notification/client
	-rm -rf ./cluster/client
	-rm -rf ./test/token/oauth
	-rm -rf ./test/generated

CLEAN_TARGETS += clean-vendor
.PHONY: clean-vendor
## Removes the ./vendor directory.
clean-vendor:
	-rm -rf $(VENDOR_DIR)

.PHONY: deps
## Download build dependencies.
deps: $(DEP_BIN) $(VENDOR_DIR)

# install dep in a the tmp/bin dir of the repo
$(DEP_BIN):
	@echo "Installing 'dep' $(DEP_VERSION) at '$(DEP_BIN_DIR)'..."
	mkdir -p $(DEP_BIN_DIR)
ifeq ($(UNAME_S),Darwin)
	@curl -L -s https://github.com/golang/dep/releases/download/$(DEP_VERSION)/dep-darwin-amd64 -o $(DEP_BIN)
	@cd $(DEP_BIN_DIR) && \
	echo "1544afdd4d543574ef8eabed343d683f7211202a65380f8b32035d07ce0c45ef  dep" > dep-darwin-amd64.sha256 && \
	shasum -a 256 --check dep-darwin-amd64.sha256
else
	@curl -L -s https://github.com/golang/dep/releases/download/$(DEP_VERSION)/dep-linux-amd64 -o $(DEP_BIN)
	@cd $(DEP_BIN_DIR) && \
	echo "31144e465e52ffbc0035248a10ddea61a09bf28b00784fd3fdd9882c8cbb2315  dep" > dep-linux-amd64.sha256 && \
	sha256sum -c dep-linux-amd64.sha256
endif
	@chmod +x $(DEP_BIN)

$(VENDOR_DIR): Gopkg.toml Gopkg.lock
	@echo "checking dependencies..."
	@$(DEP_BIN) ensure -v

app/controllers.go: $(DESIGNS) $(GOAGEN_BIN) $(VENDOR_DIR)
	$(GOAGEN_BIN) app -d ${PACKAGE_NAME}/${DESIGN_DIR}
	$(GOAGEN_BIN) controller -d ${PACKAGE_NAME}/${DESIGN_DIR} -o controller/ --pkg controller --app-pkg ${PACKAGE_NAME}/app
	$(GOAGEN_BIN) gen -d ${PACKAGE_NAME}/${DESIGN_DIR} --pkg-path=${PACKAGE_NAME}/goasupport/conditional_request --out app
	$(GOAGEN_BIN) client -d ${PACKAGE_NAME}/${DESIGN_DIR}
	$(GOAGEN_BIN) swagger -d ${PACKAGE_NAME}/${DESIGN_DIR}
	$(GOAGEN_BIN) client -d github.com/fabric8-services/fabric8-wit/design --notool --pkg witservice -o wit
	$(GOAGEN_BIN) client -d github.com/fabric8-services/fabric8-tenant/design --notool --pkg tenant -o authentication/account
	$(GOAGEN_BIN) client -d github.com/fabric8-services/fabric8-notification/design --notool --pkg client -o notification
	$(GOAGEN_BIN) client -d github.com/fabric8-services/fabric8-cluster/design --notool --pkg client -o cluster

.PHONY: migrate-database
## Compiles the server and runs the database migration with it
migrate-database: $(BINARY_SERVER_BIN)
	$(BINARY_SERVER_BIN) -migrateDatabase

.PHONY: generate
## Generate GOA sources. Only necessary after clean of if changed `design` folder.
generate: app/controllers.go migration/sqlbindata.go configuration/confbindata.go generate-minimock

.PHONY: regenerate
## Runs the "clean-generated" and the "generate" target
regenerate: clean-generated generate

.PHONY: dev
dev: prebuild-check deps generate $(FRESH_BIN)
	docker-compose up -d db
	AUTH_DEVELOPER_MODE_ENABLED=true $(FRESH_BIN)

include ./.make/test.mk
include ./.make/Makefile.dev

ifneq ($(OS),Windows_NT)
ifdef DOCKER_BIN
include ./.make/docker.mk
endif
endif

$(INSTALL_PREFIX):
# Build artifacts dir
	mkdir -p $(INSTALL_PREFIX)

$(TMP_PATH):
	mkdir -p $(TMP_PATH)
	
.PHONY: deploy-auth-openshift
deploy-auth-openshift: prebuild-check deps generate $(FRESH_BIN)
	minishift start --cpus 4
	./minishift/check_hosts.sh
	-eval `minishift oc-env` &&  oc login -u developer -p developer && oc new-project auth-openshift
	AUTH_DEVELOPER_MODE_ENABLED=true \
	kedge apply -f minishift/kedge/db-auth.yml -f minishift/kedge/auth.yml

.PHONY: dev-db-openshift
dev-db-openshift: prebuild-check deps generate $(FRESH_BIN)
	minishift start --cpus 4
	./minishift/check_hosts.sh
	-eval `minishift oc-env` &&  oc login -u developer -p developer && oc new-project auth-openshift
	AUTH_DEVELOPER_MODE_ENABLED=true \
	kedge apply -f minishift/kedge/db-auth.yml
	sleep 5s
	AUTH_POSTGRES_HOST=minishift.local \
	AUTH_POSTGRES_PORT=31001 \
	AUTH_POSTGRES_USERNAME=postgres \
	AUTH_POSTGRES_PASSWORD=mysecretpassword \
	$(FRESH_BIN)

.PHONY: dev-openshift
dev-openshift: prebuild-check deps generate build bin/docker/fabric8-auth-linux
	minishift start --cpus 4
	./minishift/check_hosts.sh
	-eval `minishift oc-env` &&  oc login -u developer -p developer && oc new-project auth-openshift
	AUTH_DEVELOPER_MODE_ENABLED=true \
	kedge apply -f minishift/kedge/db-auth.yml
	sleep 5s
	-eval `minishift docker-env` && docker login -u developer -p $$(oc whoami -t) $$(minishift openshift registry) && docker build -t fabric8/fabric8-auth:dev bin/docker
	-kedge delete -f minishift/kedge/auth-local.yml
	kedge apply -f minishift/kedge/auth-local.yml
	
.PHONY: clean-openshift
clean-openshift:
	-eval `minishift oc-env` &&  oc login -u developer -p developer
	-kedge delete -f minishift/kedge/auth.yml -f minishift/kedge/db-auth.yml
	-eval oc delete project auth-openshift --grace-period=1

.PHONY: show-info
show-info:
	$(call log-info,"$(shell go version)")
	$(call log-info,"$(shell go env)")

.PHONY: prebuild-check
prebuild-check: $(TMP_PATH) $(INSTALL_PREFIX) $(CHECK_GOPATH_BIN) show-info
# Check that all tools where found
ifndef GIT_BIN
	$(error The "$(GIT_BIN_NAME)" executable could not be found in your PATH)
endif
ifndef DEP_BIN
	$(error The "$(DEP_BIN_NAME)" executable could not be found in your PATH)
endif
	@$(CHECK_GOPATH_BIN) -packageName=$(PACKAGE_NAME) || (echo "Project lives in wrong location"; exit 1)

$(CHECK_GOPATH_BIN): .make/check_gopath.go
ifndef GO_BIN
	$(error The "$(GO_BIN_NAME)" executable could not be found in your PATH)
endif
ifeq ($(OS),Windows_NT)
	@go build -o "$(shell cygpath --windows '$(CHECK_GOPATH_BIN)')" .make/check_gopath.go
else
	@go build -o $(CHECK_GOPATH_BIN) .make/check_gopath.go
endif

.PHONY: docs
docs: asciidoctorbin-check
	@$(ASCIIDOCTOR_BIN) "$(DOCS_DIR)/source/**/*.adoc" -D $(DOCS_DIR)

.PHONY: asciidoctorbin-check
asciidoctorbin-check:
# Check that the asciidoctor tool is found
ifndef ASCIIDOCTOR_BIN
	$(error The "$(ASCIIDOCTOR_BIN_NAME)" executable could not be found in your PATH)
endif	

# Keep this "clean" target here at the bottom
.PHONY: clean
## Runs all clean-* targets.
clean: $(CLEAN_TARGETS)


bin/docker: Dockerfile.dev
	mkdir -p bin/docker
	cp Dockerfile.dev bin/docker/Dockerfile

bin/docker/fabric8-auth-linux: bin/docker $(SOURCES)
	GO15VENDOREXPERIMENT=1 GOARCH=amd64 GOOS=linux go build -o bin/docker/fabric8-auth-linux

fast-docker: bin/docker/fabric8-auth-linux
	docker build -t fabric8/fabric8-auth:dev bin/docker

kube-redeploy: fast-docker
	kubectl delete pod -l service=auth

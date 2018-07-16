## Running Auth, WIT, Fabric8 ui services on OpenShift

These instructions will help you run your services on OpenShift using MiniShift.

### Prerequisites

[MiniShift v1.21.0](https://docs.openshift.org/latest/minishift/getting-started/installing.html)

[oc 3.9.0](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

[KVM Hypervisor](https://www.linux-kvm.org/page/Downloads)

#### Install Minishift

Make sure you have all prerequisites installed. Please check the list [here](https://docs.openshift.org/latest/minishift/getting-started/installing.html#install-prerequisites)

Download and put `minishift` in your $PATH by following steps [here](https://docs.openshift.org/latest/minishift/getting-started/installing.html#manually)

Verify installation by running following command, you should get version number.
```bash
minishift version
```

#### Install oc
Please install and set up oc on your machine by visiting [oc](https://docs.openshift.org/latest/cli_reference/get_started_cli.html#installing-the-cli)

Verify installation by running following command, you should get version number.
```bash
oc version
```

### Deploying services on Minishift
Here, we are going to deploy `auth`, `wit`, `fabric8-ui` services on minishift.

#### Start Minishift
We have make target defined to start minishift with reqquired cpu's and configuration.
```bash
make minishift-start
```
Please enter sudo password when prompted, it is needed in order to create an entry in the `/etc/hosts`.
`minishift ip` gives the IP address on which MiniShift is running. This automation creates a host entry as `minishift.local` for that IP. This domain is whitelisted on fabric8-auth.

Make sure to verify that your console is configured to reuse the Minishift Docker daemon by running `docker ps` command. You should be able to see running containers for origin.
If not then follow [this](https://docs.openshift.org/latest/minishift/using/docker-daemon.html#docker-daemon-overview) guide to configure it.

#### Create a Project
Let's create a new project by executing following make target.
```bash
make init-project
```

This will create a new project with name `fabric8-services` with `developer:developer` account and switch to it. Make sure to verify that using `oc project`.

#### Auth Service
##### Deploying Auth

To deploy auth service, we have following make target which will deploy required secrets, postgres DB and create routes for you.
```
make deploy-auth
```

Look for running pods using `oc get pods`. You should be able to see two pods(auth-*, db-auth-*). First time it will take some time as it has download required container images.

##### Check auth service status
You can get auth route by using `oc get routes`. It should be in format `auth-fabric8-services.${minishift ip}.nip.io`
You can check status by hitting this in browser `http://auth-fabric8-services.${minishift ip}.nip.io/api/status`(e.g. `http://auth-fabric8-services.192.168.42.177.nip.io/api/status`).

##### Connecting to Postgres DB
If you wish to access the Postgres database, it is available on the same host but on port 31001.  Use the following command to connect with the Postgres client:

```bash
PGPASSWORD=mysecretpassword psql -h minishift.local -U postgres -d postgres -p 31001
```

#### WIT Service
##### Deploying WIT

To deploy wit service, we have following make target which will deploy required secrets, config map, postgres DB and create routes for you.
```
make deploy-wit
```

Look for running pods using `oc get pods`. You should be able to see two pods(wit-*, db-wit-*). First time it will take some time as it has download required container images.

##### Check wit service status
You can get auth route by using `oc get routes`. It should be in format `wit-fabric8-services.${minishift ip}.nip.io`
You can check status by hitting this in browser `http://wit-fabric8-services.${minishift ip}.nip.io/api/status`(e.g. `http://wit-fabric8-services.192.168.42.177.nip.io/api/status`).

##### Connecting to Postgres DB
If you wish to access the Postgres database, it is available on the same host but on port 31002.  Use the following command to connect with the Postgres client:

```bash
PGPASSWORD=mysecretpassword psql -h minishift.local -U postgres -d postgres -p 31002
```

#### Fabric8 UI Service
##### Deploying Fabric8 UI

To deploy fabric8 UI service, we have following make target which will deploy service, and create routes for you.
```bash
make deploy-f8ui
```

Look for running pods using `oc get pods`. You should be able to see two pods(f8ui-*). First time it will take some time as it has download required container images.

##### Check f8ui service status
You can get f8ui route by using `oc get routes`. It should be in format `f8ui-fabric8-services.${minishift ip}.nip.io`
You can try logging by hitting this in browser `http://f8ui-fabric8-services.${minishift ip}.nip.io`(e.g. `http://f8ui-fabric8-services.192.168.42.177.nip.io`).

Note: However if you are trying this first time you should approve your username from keycloak, so that you will be authenticated user.
Also make sure to whitelist the domain which you are using for auth to work it as per expectation.

#### Deploying Auth, WIT, UI together
To deploy `auth`, `wit`, `fabric8-ui` together we have following target:
```bash
make deploy-dev-all
```

#### Cleaning Up

##### Cleaning Auth
This removes both the `auth` and `db-auth` services from minishift.
```bash
make clean-auth
```

##### Cleaning WIT
This removes both the `wit` and `db-wit` services from minishift.
```bash
make clean-wit
```

##### Cleaning Fabric8-ui
This removes both the `fabric8-ui` service from minishift.
```bash
make clean-f8ui
```

##### Cleaning Auth, WIT, Fabric8-UI
This removes `auth`, `wit`, `fabric8-ui` services from minishift and deletes the `fabric8-services` project.
```bash
make clean-dev-all
```

#### Redeploying Auth service
However if you are working on auth service and wants to redeploy latest code change by building container with latest bniary. We have
special target for it which will do that for you.

It won't deploy required secrets and postgres db again. It'll re-deploy auth service only.

```bash
make redeploy-auth
```

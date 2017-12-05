## Start running dependent services on OpenShift

These instructions will help you run your services on OpenShift using MiniShift.

### Prerequisites


[Kedge](kedgeproject.org)

[MiniShift](https://docs.openshift.org/latest/minishift/getting-started/installing.html)

[Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)


### Installation (Linux)

##### Install Kedge

Following steps will download and install Kedge on your machine and put it in your $PATH. For more detailed information please visit kedgeproject.org

```
curl -L https://github.com/kedgeproject/kedge/releases/download/v0.5.1/kedge-linux-amd64 -o kedge
```

Verify installation by running following command, you should get version number.

```
kedge version
```

##### Install Minishift

Make sure you have all prerequisites installed. Please check the list [here](https://docs.openshift.org/latest/minishift/getting-started/installing.html#install-prerequisites)

Download and put `minishift` in your $PATH by following steps [here](https://docs.openshift.org/latest/minishift/getting-started/installing.html#manually)

Verify installation by running following command, you should get version number.
```
minishift version
```


##### Install Kubectl

Please install and set up Kubectl on your machine by visiting [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

Verify installation by running following command, you should get version number.
```
kubectl version
```

End with an example of getting some data out of the system or using it for a little demo

## Usage

See the developer documentation for make targets to run fabric8-auth on minishift

## Check logs from services
Use `oc` from MiniShift
```
eval $(minishift oc-env)
```

List out all running services in MiniShift using
```
oc get pods
```
Wait until all pods are in running state and then copy pod name and use following command to see logs
```
oc logs <<pod name>> -f
```

Use `docker` from MiniShift
```
eval $(minishift docker-env)
```
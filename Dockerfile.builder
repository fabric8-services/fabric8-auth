FROM centos:7
LABEL maintainer "Devtools <devtools@redhat.com>"
LABEL author "Konrad Kleine <kkleine@redhat.com>"
ENV LANG=en_US.utf8
ARG USE_GO_VERSION_FROM_WEBSITE

# Some packages might seem weird but they are required by the RVM installer.

RUN yum install epel-release --enablerepo=extras -y
RUN yum install --enablerepo=epel-testing -y \
      findutils \
      git \
      $(test -z "$USE_GO_VERSION_FROM_WEBSITE" && echo "golang") \
      make \
      procps-ng \
      tar \
      wget \
      which \
    && yum clean all

RUN test -n "$USE_GO_VERSION_FROM_WEBSITE" \
    && cd /tmp \
    && wget https://dl.google.com/go/go1.11.1.linux-amd64.tar.gz \
    && echo "2871270d8ff0c8c69f161aaae42f9f28739855ff5c5204752a8d92a1c9f63993  go1.11.1.linux-amd64.tar.gz" > checksum \
    && sha256sum -c checksum \
    && tar -C /usr/local -xzf go1.11.1.linux-amd64.tar.gz \
    && rm -f go1.11.1.linux-amd64.tar.gz \
    || echo 
ENV PATH=$PATH:/usr/local/go/bin

# Get dep for Go package management and make sure the directory has full rwz permissions for non-root users
ENV GOPATH /tmp/go
RUN mkdir -p $GOPATH/bin && chmod a+rwx $GOPATH
RUN cd $GOPATH/bin \
	curl -L -s https://github.com/golang/dep/releases/download/v0.4.1/dep-linux-amd64 -o dep \
	echo "31144e465e52ffbc0035248a10ddea61a09bf28b00784fd3fdd9882c8cbb2315  dep" > dep-linux-amd64.sha256 \
	sha256sum -c dep-linux-amd64.sha256

ENTRYPOINT ["/bin/bash"]

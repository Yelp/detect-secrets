FROM registry.access.redhat.com/ubi8/python-39
LABEL maintainer="squad:git-defenders" url="https://github.ibm.com/whitewater/whitewater-detect-secrets"

User root
RUN yum -y update

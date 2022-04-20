FROM registry.access.redhat.com/ubi8-minimal
LABEL maintainer="squad:git-defenders" url="https://github.ibm.com/whitewater/whitewater-detect-secrets"

User root
# install python 3.8 and corresponding pip ... install git (used in DS scan)
RUN microdnf -y install python38 python38-pip git
RUN microdnf -y update

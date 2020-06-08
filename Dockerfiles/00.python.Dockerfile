FROM python:3
LABEL maintainer="squad:git-defenders" url="https://github.ibm.com/whitewater/whitewater-detect-secrets"

RUN apt-get -y remove --purge mysql*
RUN apt-get update && apt-get upgrade -y
RUN pip install --upgrade pip

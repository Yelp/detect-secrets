FROM python:3
LABEL maintainer="squad:git-defenders" url="https://github.com/IBM/detect-secrets"

RUN \
  apt-get update && \
  apt-get -y remove --purge mysql* && \
  apt-get upgrade -y && \
  rm -rf /var/lib/apt/lists/* && \
  pip install --upgrade pip

FROM python:3
LABEL maintainer="squad:git-defenders" url="https://github.ibm.com/whitewater/whitewater-detect-secrets"

RUN apt-get -y remove --purge mysql*
# Remediate CVE-2019-18218
RUN apt-get update && apt-get install file -y
RUN pip install --upgrade pip

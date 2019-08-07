FROM python:alpine
MAINTAINER toolbox-dev@us.ibm.com
RUN apk add --no-cache jq git curl bash openssl
RUN mkdir -p /code
COPY . /usr/src/app
WORKDIR /usr/src/app
RUN easy_install /usr/src/app
WORKDIR /code
ENTRYPOINT [ "/usr/src/app/run-scan.sh" ]

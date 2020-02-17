FROM git-defenders/python

RUN apt-get update && apt-get install -y jq
RUN mkdir -p /code
COPY . /usr/src/app
WORKDIR /usr/src/app
RUN pip install /usr/src/app
WORKDIR /code
ENTRYPOINT [ "/usr/src/app/run-scan.sh" ]

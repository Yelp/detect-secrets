FROM git-defenders/python

# Auto adjust line ending. Support running scan on Windows platform
RUN git config --global core.autocrlf true

COPY README.md /code/
COPY setup.py /code/
COPY setup.cfg /code/
COPY detect_secrets /code/detect_secrets

RUN pip install /code

WORKDIR /code

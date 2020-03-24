FROM git-defenders/python

# Auto adjust line ending. Support running scan on Windows platform
RUN git config --system core.autocrlf true
# Improve performace when creating index across Windows and Linux platform
RUN git config --system core.checkStat minimal

COPY README.md /code/
COPY setup.py /code/
COPY setup.cfg /code/
COPY detect_secrets /code/detect_secrets

RUN pip install /code

WORKDIR /code

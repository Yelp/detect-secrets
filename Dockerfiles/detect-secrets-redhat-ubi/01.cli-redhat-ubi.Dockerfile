FROM git-defenders/python-redhat-ubi

COPY README.md /code/
COPY setup.py /code/
COPY setup.cfg /code/
COPY detect_secrets /code/detect_secrets

RUN pip install /code

COPY scripts/run-in-pipeline.sh /
WORKDIR /code

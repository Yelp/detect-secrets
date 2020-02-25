FROM python:3.8-slim

RUN pip install detect-secrets

ENTRYPOINT ["detect-secrets"]
CMD ["--help"]

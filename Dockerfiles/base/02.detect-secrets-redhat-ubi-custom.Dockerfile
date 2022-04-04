FROM git-defenders/detect-secrets-redhat-ubi

COPY scripts/run-in-pipeline.sh /

ENTRYPOINT [ "/run-in-pipeline.sh" ]
CMD [ ]

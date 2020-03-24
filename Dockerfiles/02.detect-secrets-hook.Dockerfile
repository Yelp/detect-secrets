FROM git-defenders/cli

RUN git config --system core.safecrlf false
ENTRYPOINT [ "detect-secrets-hook" ]

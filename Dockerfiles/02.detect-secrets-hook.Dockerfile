FROM git-defenders/cli

RUN git config --global core.safecrlf false
ENTRYPOINT [ "detect-secrets-hook" ]

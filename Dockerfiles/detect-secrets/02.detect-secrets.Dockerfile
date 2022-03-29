FROM git-defenders/cli
ENTRYPOINT [ "detect-secrets" ]
CMD [ "scan", "/code" ]

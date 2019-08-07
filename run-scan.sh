#!/bin/sh
echo "Scanning the code"

# setting variables
if [ -n "$CODE" ]
then
  cd "$CODE" || exit 1
fi
if [ -z "$BASEFILE" ]
then
  BASEFILE=".secrets.baseline"
fi

# running the audit for user to mark secret as valid or invalid
if [ "$1" = "audit" ]
then
  detect-secrets audit "$BASEFILE"
  exit $?
else
  # get the secrets which are valid
  get_non_resolve_secret_count() {
    jq -r ".results | flatten | map(select( if .is_secret == null then true else .is_secret end )) | length" "$BASEFILE"
  }

  # Scanning
  if [ ! -f "$BASEFILE" ]
  then
    detect-secrets scan > "$BASEFILE"
  else
    detect-secrets scan --update "$BASEFILE"
  fi

  if [ "$(get_non_resolve_secret_count)" -gt 0 ]
  then
    echo "Have secrets in code, please run audit to see what the secrets"
    exit 1
  else
    echo "Scanned no secrets found"
    exit 0
  fi
fi

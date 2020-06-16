#!/bin/bash
#
# This script generate Pipfile based on pip freeze output

echo "[[source]]
name = \"pypi\"
url = \"https://pypi.org/simple\"
verify_ssl = true

[requires]
python_version = \"$(python --version | cut -d' ' -f2)\"
"

echo "[packages]"
for pkg in $(pip freeze | grep -v ' @ '); do
  echo $pkg | awk -F= '{str = sprintf("%s = \"==%s\"", $1, $3)} END {print str}'
done

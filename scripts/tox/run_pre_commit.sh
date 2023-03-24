#!/bin/bash

if [ "$SKIP_PRE_COMMIT" == true ]; then echo "Skipping pre-commit run."
else
    pre-commit run --all-files --show-diff-on-failure
fi

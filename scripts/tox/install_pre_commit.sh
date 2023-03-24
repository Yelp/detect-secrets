#!/bin/bash

if [ "$SKIP_PRE_COMMIT" == true ]; then echo "Skipping pre-commit installation."
else
    pre-commit install -f --install-hooks
fi

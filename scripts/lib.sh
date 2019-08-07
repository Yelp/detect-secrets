#!/bin/bash
GITHUB_URL="https://github.ibm.com"
# generate a JWT token used for github apps
# INPUT
# $1 Is the github app id
# $2 Is the private key for the github app
GENERATE_JWT_TOKEN() {
    local IAT
    local EXP
    local HEADER
    local PAYLOAD
    local ISS
    local ALG
    local PRIVATE_KEY
    local COMBINE_HEADER
    local SIGNATURE
    IAT=$(date +%s) # the time of issue
    EXP=$((IAT + 60 * 10)) # the time it expire the ma time is 10 minutes
    ISS="$1" # The issue which is the github app id
    ALG="RS256" # The alogrith used for encoding
    PRIVATE_KEY="$2" # private key to sign with

    HEADER="{\"alg\":\"$ALG\"}"
    PAYLOAD="{\"iat\":$IAT,\"exp\":$EXP,\"iss\":\"$ISS\"}"

    encode() {
        echo -n "$1" | openssl enc -base64 -A
    }

    sign() {
        echo -n "$1" | openssl dgst -sha256 -sign "$2" | openssl enc -base64 -A
    }

    COMBINE_HEADER="$(encode "$HEADER").$(encode "$PAYLOAD")"
    SIGNATURE=$(sign "$COMBINE_HEADER" "$PRIVATE_KEY")

    echo -n "$COMBINE_HEADER.$SIGNATURE"
}

# Get the token for the installation to be used for the repo
# Input
# $1 Is the github app id
# $2 Is the private key for the github app
# $3 the installation id

GET_INSTALLATION_TOKEN() {
    local JWT_TOKEN
    JWT_TOKEN=$(GENERATE_JWT_TOKEN "$1" "$2")
    curl -X POST \
        -s \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -H "Accept: application/vnd.github.machine-man-preview+json" \
        "$GITHUB_URL/api/v3/installations/$3/access_tokens" | jq -r ".token"
}

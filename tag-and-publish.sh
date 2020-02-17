#!/bin/bash -e

script_name=$(basename $0)

if [ $# -lt 2 ]; then
    echo "Usage: $script_name local_image_with_tag remote_image_with_tag"
    exit 1
fi

LOCAL_IMAGE=$1
REMOTE_IAMGE=$2

docker tag $LOCAL_IMAGE $REMOTE_IAMGE
docker push $REMOTE_IAMGE

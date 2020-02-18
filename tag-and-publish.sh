#!/bin/bash -e

script_name=$(basename $0)

if [ $# -lt 4 ]; then
    echo "Usage: $script_name image_names local_domain_name remote_domain_names tags"
    exit 1
fi

DOCKER_IMAGES=$1
DOCKER_DOMAIN_LOCAL=$2
DOCKER_DOMAIN_REMOTES=$3
TAG_NAMES=$4

for image_name in $DOCKER_IMAGES
do
    for domain_name in $DOCKER_DOMAIN_REMOTES
    do
        for tag in $TAG_NAMES
        do
            docker tag $DOCKER_DOMAIN_LOCAL/$image_name $domain_name/$image_name:$tag
            docker push $domain_name/$image_name:$tag
        done
    done
done

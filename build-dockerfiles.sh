#!/bin/bash -ex

CUR_DIR=$(dirname $0)
pushd "${CUR_DIR}"

IMAGE_DOMAIN=git-defenders

# build images
for dockerfile in Dockerfiles/*.Dockerfile
do
    image_name=$(echo -e $(basename ${dockerfile}) | cut -d\. -f2)
    docker build -f "${dockerfile}" -t $IMAGE_DOMAIN/$image_name .
done

# test images
docker run -it $IMAGE_DOMAIN/detect-secrets --version
docker run -it $IMAGE_DOMAIN/detect-secrets-hook --version

popd

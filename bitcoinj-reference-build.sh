#!/bin/bash
# Run reference-container-build.sh before using this script
# The output will be produced in the same location as a locally hosted build
docker run --rm --name bitcoinj-reference-build -v .:/project -it \
    bitcoinj/reference-build:latest \
    /usr/bin/gradle --no-build-cache --no-daemon --no-parallel --project-dir /project/ \
        :bitcoinj-core:build :bitcoinj-wallettool:installDist

#!/bin/bash
#
# This script builds a Container image that can be used to run a reference build of bitcoinj.
# Run this script to build the container and then use bitcoinj-reference-build.sh to
# make the reference build of bitcoinj.
# When building the continer `apt-get update` and `apt-get install` are run once and can
# then be reused for multiple builds of bitcoinj.
#
docker build --file reference-container.ContainerFile -t bitcoinj/reference-build .


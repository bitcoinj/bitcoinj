#
# Reproducible reference build
#
# Usage:
#
# buildah build --file build.Containerfile --output <outputdir> .
# or
# podman build --file build.Containerfile --output <outputdir> .
# or
# docker build --file build.Containerfile --output <outputdir> .
#
# The build artifacts are written to the specified output directory.
# To also run tests, add
#
# --build-arg ADDITIONAL_GRADLE_TASK=test
#

# stage: set up debian environment
FROM debian:bookworm-slim AS setup-stage

ENV DEBIAN_FRONTEND noninteractive
RUN /usr/bin/apt-get update && \
    /usr/bin/apt-get --yes install openjdk-17-jdk-headless gradle && \
    /usr/sbin/adduser --disabled-login --gecos "" builder

# stage: download dependencies
FROM setup-stage as download-stage

# give up privileges
USER builder
WORKDIR /home/builder

# copy project source code
COPY --chown=builder / project/

# download
RUN /usr/bin/gradle --project-dir project/ \
    --no-build-cache --no-daemon --no-parallel \
    --settings-file=settings-debian.gradle \
    -Dmaven.repo.local=repo \
    clean ${ADDITIONAL_GRADLE_TASK} :bitcoinj-base:publishToMavenLocal :bitcoinj-core:publishToMavenLocal :bitcoinj-wallettool:installDist

# stage: build
FROM setup-stage AS build-stage

ARG ADDITIONAL_GRADLE_TASK=""

# give up privileges
USER builder
WORKDIR /home/builder

# copy project source code and downloaded repo
COPY --chown=builder / project/
COPY --from=download-stage /home/builder/.gradle /home/builder/.gradle

# build project
RUN --network=none \
    /usr/bin/gradle --project-dir project/ \
    --offline --no-build-cache --no-daemon --no-parallel \
    --settings-file=settings-debian.gradle \
    -Dmaven.repo.local=repo \
    clean ${ADDITIONAL_GRADLE_TASK} :bitcoinj-base:publishToMavenLocal :bitcoinj-core:publishToMavenLocal :bitcoinj-wallettool:installDist

# stage: export build output
FROM scratch AS export-stage
COPY --from=build-stage \
    /home/builder/repo/org/bitcoinj/bitcoinj-base/*/*.jar \
    /home/builder/repo/org/bitcoinj/bitcoinj-base/*/*.pom \
    /base/
COPY --from=build-stage \
    /home/builder/repo/org/bitcoinj/bitcoinj-core/*/*.jar \
    /home/builder/repo/org/bitcoinj/bitcoinj-core/*/*.pom \
    /core/
COPY --from=build-stage \
    /home/builder/project/wallettool/build/install/wallet-tool/ \
    /wallettool/

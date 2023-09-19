FROM debian:bookworm-slim

# prepare debian environment
ENV DEBIAN_FRONTEND noninteractive
RUN /usr/bin/apt-get update && \
    /usr/bin/apt-get --yes install openjdk-17-jdk-headless gradle

# Container image that runs your code
FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
  build-essential \
  git \
  libgmp-dev \
  && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
CMD ./entrypoint.sh
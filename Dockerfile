# Container image that runs your code
FROM alpine:3.10

RUN apk add git
RUN apk add build-base

COPY entrypoint.sh /entrypoint.sh
CMD ./entrypoint.sh
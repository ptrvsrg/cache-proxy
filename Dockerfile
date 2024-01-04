FROM alpine:latest AS build
WORKDIR /cache-proxy
RUN apk add --no-cache build-base make
COPY . /cache-proxy
RUN make build

FROM alpine:latest
COPY --from=build /cache-proxy/build/* cache-proxy
EXPOSE 8080
ENTRYPOINT ["/cache-proxy", "8080"]
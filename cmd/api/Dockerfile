FROM golang:1.27.3-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/api ./cmd/api
RUN CGO_ENABLED=0 go build -trimpath -o /service ./cmd/api

FROM alpine:3.24.3
RUN mkdir /data && chown 65532:65532 /data && chmod 700 /data
COPY --from=build /service /service
USER 65532:65532
ENTRYPOINT ["/service"]

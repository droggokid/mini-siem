FROM golang:1.27.3-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/event ./cmd/event
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /service ./cmd/event

FROM alpine:3.24.3
RUN mkdir -p /run/event-auth && chown 65532:65532 /run/event-auth && chmod 700 /run/event-auth
COPY --from=build /service /service
USER 65532:65532
ENTRYPOINT ["/service"]

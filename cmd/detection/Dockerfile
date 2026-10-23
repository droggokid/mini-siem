FROM golang:1.27.3-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/detection ./cmd/detection
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /service ./cmd/detection

FROM alpine:3.24.3
COPY --from=build /service /service
USER 65532:65532
ENTRYPOINT ["/service"]

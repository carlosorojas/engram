FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -o /out/engram ./cmd/engram

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -u 10001 engram
COPY --from=builder /out/engram /usr/local/bin/engram
COPY --chmod=0755 docker/cloud/entrypoint.sh /usr/local/bin/entrypoint.sh
USER engram
WORKDIR /home/engram

EXPOSE 18080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["cloud", "serve"]

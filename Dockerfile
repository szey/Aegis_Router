FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aegis-router ./cmd/server

FROM alpine:3.22
LABEL org.opencontainers.image.title="Aegis_Router" \
      org.opencontainers.image.description="Framework-agnostic execution permits for AI agent tool calls. Authorize once; execute exactly what was authorized." \
      org.opencontainers.image.source="https://github.com/szey/Aegis_Router"
RUN addgroup -S agentgw && adduser -S -G agentgw agentgw
WORKDIR /app
COPY --from=build /out/aegis-router /usr/local/bin/aegis-router
COPY configs ./configs
COPY examples ./examples
RUN mkdir -p /app/data && chown -R agentgw:agentgw /app/data
USER agentgw
EXPOSE 8080
ENTRYPOINT ["aegis-router", "--addr", ":8080"]

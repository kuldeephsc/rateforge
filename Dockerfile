# syntax=docker/dockerfile:1

# --- build stage ----------------------------------------------------------
FROM golang:1.22 AS build
WORKDIR /src

# Sentinel has zero external dependencies (see go.mod), so there is no
# `go mod download` layer to cache separately — copying everything and
# building directly is simplest and still fast.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/sentinel ./cmd/sentinel
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/simulator ./cmd/simulator

# --- runtime stage ----------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

WORKDIR /app
COPY --from=build /out/sentinel /app/sentinel
COPY --from=build /out/simulator /app/simulator
COPY configs/sentinel.yaml /app/configs/sentinel.yaml

# distroless:nonroot already runs as uid 65532 ("nonroot"); no extra user
# setup needed. Filesystem is otherwise read-only at the image layer; mount
# /app/certs and /app/logs as writable volumes if TLS/audit-file logging to
# disk is needed at runtime.
USER nonroot:nonroot

EXPOSE 8080 9090 9100

ENTRYPOINT ["/app/sentinel"]
CMD ["--config", "/app/configs/sentinel.yaml"]

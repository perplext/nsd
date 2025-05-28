# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libpcap-dev git

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Build the binary
RUN CGO_ENABLED=1 go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o nsd ./cmd/nsd

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache libpcap ca-certificates tzdata && \
    adduser -D -s /bin/false nsd

# Copy binary from builder
COPY --from=builder /build/nsd /usr/local/bin/nsd

# Copy default configuration
RUN mkdir -p /etc/nsd /var/log/nsd /var/lib/nsd && \
    chown -R nsd:nsd /var/log/nsd /var/lib/nsd

# Copy configuration template
COPY --from=builder /build/docs/examples/config.json /etc/nsd/config.example.json

# Set up volumes
VOLUME ["/etc/nsd", "/var/log/nsd", "/var/lib/nsd"]

# Expose metrics port
EXPOSE 9100

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nsd -version || exit 1

# Run as root initially (will drop privileges)
USER root

# Default command
ENTRYPOINT ["/usr/local/bin/nsd"]
CMD ["-config", "/etc/nsd/config.json"]
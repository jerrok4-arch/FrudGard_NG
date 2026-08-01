FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fraudguard-ng .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/fraudguard-ng .

# Copy MaxMind DB (mount at runtime)
# COPY GeoIP2-City.mmdb .

EXPOSE 8080

CMD ["./fraudguard-ng"]

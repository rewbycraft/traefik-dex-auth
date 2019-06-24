FROM golang:1.11-alpine as builder

# Setup
RUN mkdir /app
WORKDIR /app

# Add libraries
RUN apk add --no-cache git && \
  go get "github.com/coreos/go-oidc" && \
  go get "github.com/gorilla/sessions" && \
  go get "golang.org/x/net/context" && \
  go get "golang.org/x/oauth2" && \
  apk del git

# Copy & build
ADD . /app/
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o /traefik-dex-auth .

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-dex-auth /
ENTRYPOINT ["/traefik-dex-auth"]


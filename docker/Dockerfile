FROM cgr.dev/chainguard/go AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.Version=${VERSION}" -o /vault-sync ./cmd/vault-sync

FROM cgr.dev/chainguard/wolfi-base

RUN apk update && apk add --no-cache ripgrep && rm -rf /var/cache/apk/*

COPY --from=builder /vault-sync /usr/local/bin/vault-sync

ENTRYPOINT ["vault-sync"]

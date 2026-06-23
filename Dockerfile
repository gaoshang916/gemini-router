# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/gemini-router .

FROM alpine:3.20
RUN adduser -D -H -u 10001 appuser
WORKDIR /app
COPY --from=builder /out/gemini-router /usr/local/bin/gemini-router
RUN mkdir -p /data && chown -R appuser:appuser /data
USER appuser
ENV ADDR=:8080 DATA_PATH=/data/config.json GEMINI_ENDPOINT=https://generativelanguage.googleapis.com
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["gemini-router"]

FROM golang:1.25.6-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

RUN git clone https://github.com/Salastil/Sneedchat-Discord-Bridge-Go.git .

RUN go mod tidy && go build -o Sneedchat-Discord-Bridge .

FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /build/Sneedchat-Discord-Bridge .

ENTRYPOINT ["./Sneedchat-Discord-Bridge"]

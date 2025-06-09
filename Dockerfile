FROM docker.io/library/golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o webhook .

RUN apk --no-cache add ca-certificates

# Enable extensive debug logging
ENV KLOG_V=4
ENV KLOG_LOGTOSTDERR=true
ENV KLOG_ALSOLOGTOSTDERR=true
ENV KLOG_STDERRTHRESHOLD=INFO

EXPOSE 8443

CMD ["./webhook"]
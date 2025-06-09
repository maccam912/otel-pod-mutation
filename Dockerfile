FROM docker.io/library/golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o webhook .

FROM docker.io/library/alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/webhook .

RUN chmod +x webhook

# Enable extensive debug logging
ENV KLOG_V=4
ENV KLOG_LOGTOSTDERR=true
ENV KLOG_ALSOLOGTOSTDERR=true
ENV KLOG_STDERRTHRESHOLD=INFO

USER 65534:65534

EXPOSE 8443

CMD ["./webhook"]
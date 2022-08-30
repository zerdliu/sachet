FROM golang:1.18 AS builder

WORKDIR /build

COPY . .

RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -mod vendor -o sachet /build/cmd/sachet #github.com/zerdliu/sachet/cmd/sachet

FROM alpine:3.15

COPY --from=builder /build/sachet /usr/local/bin
COPY --chown=nobody templates/general.tmpl /etc/sachet/general.tmpl
COPY --chown=nobody examples/config.yaml /etc/sachet/config.yaml
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && apk update && \
    apk add --no-cache ca-certificates

USER nobody
EXPOSE 9876
ENTRYPOINT ["sachet"]
CMD ["-config", "/etc/sachet/config.yaml"]

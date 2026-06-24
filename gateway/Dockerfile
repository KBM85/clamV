FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/avgateway .

FROM alpine:3.20
RUN adduser -D -u 10001 appuser
COPY --from=build /out/avgateway /usr/local/bin/avgateway
USER appuser
EXPOSE 8090 8091
ENTRYPOINT ["/usr/local/bin/avgateway"]

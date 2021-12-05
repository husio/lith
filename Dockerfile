FROM golang:alpine AS builder

RUN apk update && apk add --no-cache make upx git ca-certificates gcc musl-dev

ENV USER=appuser
ENV UID=10001
RUN adduser \
	--disabled-password \
	--gecos "" \
	--home "/nonexistent" \
	--shell "/sbin/nologin" \
	--no-create-home \
	--uid "${UID}" "${USER}"


WORKDIR /src
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . /src/
RUN make build
RUN upx ./bin/lith

FROM alpine
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/bin/lith /bin/lith
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
USER appuser:appuser
ENTRYPOINT ["/bin/lith"]
CMD ["serve"]

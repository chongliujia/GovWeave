# A supported Go patch release, pinned for reproducible builds.
ARG GO_VERSION=1.26.9
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOPROXY=off go build -trimpath -o /out/govweave ./cmd/govweave
RUN mkdir -p /out/data && chmod 0700 /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/govweave /govweave
COPY --from=build --chown=65532:65532 /out/data /data
COPY LICENSE /licenses/GovWeave-LICENSE
COPY THIRD_PARTY_NOTICES /licenses/THIRD_PARTY_NOTICES
COPY --from=build /usr/share/doc/ca-certificates/copyright /licenses/ca-certificates-copyright
USER 65532:65532
ENV GOVWEAVE_LISTEN_ADDR=0.0.0.0:8080 GOVWEAVE_DATA_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/govweave"]

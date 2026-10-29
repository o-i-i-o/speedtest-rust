# Build
FROM rust:1 as builder
WORKDIR /usr/local/src
COPY . .
RUN cargo build --release

# Run
FROM debian:12
WORKDIR /usr/local/bin
COPY --from=builder \
	/usr/local/src/target/release/librespeed-rs \
	librespeed-rs
COPY configs.toml configs.toml
COPY assets assets
# the offline geoip fallback is opened as ./country_asn.mmdb relative to the working dir
COPY country_asn.mmdb country_asn.mmdb
EXPOSE 8080
CMD ["librespeed-rs"]

# picoquicdemo, built from a pinned picoquic commit, for the multipath interop tests in this directory.
# picoquic implements draft-ietf-quic-multipath (code points of draft 20 and 21, enabled with -M).
# picotls is fetched by picoquic's build, at the commit pinned by picoquic.
FROM debian:bookworm-slim AS builder

RUN apt-get update && \
  apt-get install -y --no-install-recommends build-essential ca-certificates cmake git libssl-dev pkg-config && \
  rm -rf /var/lib/apt/lists/*

ARG PICOQUIC_COMMIT=01e124ebdf9fc50df307e01e71f2744471ddc470

WORKDIR /src/picoquic
RUN git init -q . && \
  git remote add origin https://github.com/private-octopus/picoquic.git && \
  git fetch -q --depth 1 origin ${PICOQUIC_COMMIT} && \
  git checkout -q FETCH_HEAD

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DPICOQUIC_FETCH_PTLS=ON -DBUILD_TESTING=OFF && \
  cmake --build build --target picoquicdemo -j 4

FROM debian:bookworm-slim

RUN apt-get update && \
  apt-get install -y --no-install-recommends libssl3 && \
  rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/picoquic/build/picoquicdemo /usr/local/bin/picoquicdemo

WORKDIR /work
ENTRYPOINT ["picoquicdemo"]

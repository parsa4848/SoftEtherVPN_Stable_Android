FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git ca-certificates libssl-dev libreadline-dev libncurses-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /opt
RUN git clone --depth 1 --branch v4.44-9807-rtm https://github.com/SoftEtherVPN/SoftEtherVPN_Stable.git stable
WORKDIR /opt/stable
RUN test "$(git rev-parse HEAD)" = ed17437af9719ac66acab30faa29e375d613c35f && cp src/makefiles/linux_64bit.mak Makefile && make -j2

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 libreadline8 libncurses6 zlib1g ca-certificates openssl python3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/stable/bin/vpnserver/ /opt/server/
COPY --from=build /opt/stable/bin/vpncmd/ /opt/vpncmd/
COPY entrypoint.sh /opt/entrypoint.sh
WORKDIR /opt/server
EXPOSE 5555 53/udp 40000-40100/udp
ENTRYPOINT ["/bin/sh", "/opt/entrypoint.sh"]

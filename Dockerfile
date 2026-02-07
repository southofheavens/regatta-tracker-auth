FROM alpine:3.23.3
COPY . ./app

RUN apk add --no-cache \
    openssl-dev \
    pkgconfig \
    git \
    build-base \
    meson \
    poco-dev \
    libsodium-dev

WORKDIR /app

RUN meson build
RUN meson compile -C build -j 12

CMD ["./build/rgt-auth"]
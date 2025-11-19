# kakadu-base/Dockerfile

ARG KAKADU_DIR=v8_6-01382N

# ================================
# Stage 1: build Kakadu per-arch
# ================================
FROM ubuntu:24.04 AS build

ARG TARGETARCH
ARG KAKADU_DIR

RUN apt-get update && apt-get install -y \
    build-essential \
    ca-certificates \
    default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/default-java

WORKDIR /src/kakadu

# Copy Kakadu source tree into the image
COPY ${KAKADU_DIR}/ /src/kakadu/

# Build Kakadu and copy correct bin+libs into /opt/kakadu
RUN set -e; \
  cd make; \
  case "$TARGETARCH" in \
    amd64) \
      KDU_MAKE="Makefile-Linux-x86-64-gcc"; \
      KDU_BINDIR="../bin/Linux-x86-64-gcc"; \
      KDU_LIBDIR="../lib/Linux-x86-64-gcc"; \
      ;; \
    arm64) \
      KDU_MAKE="Makefile-Linux-arm-64-gcc"; \
      KDU_BINDIR="../bin/Linux-arm-64-gcc"; \
      KDU_LIBDIR="../lib/Linux-arm-64-gcc"; \
      ;; \
    *) \
      echo "Unsupported arch: $TARGETARCH" >&2; \
      exit 1; \
      ;; \
  esac; \
  echo "Building Kakadu with $KDU_MAKE for $TARGETARCH"; \
  MAKEFLAGS= make -f "$KDU_MAKE" -j1; \
  mkdir -p /opt/kakadu/bin /opt/kakadu/lib; \
  echo "Copying executables from $KDU_BINDIR to /opt/kakadu/bin"; \
  cp "$KDU_BINDIR"/* /opt/kakadu/bin/; \
  echo "Copying libs from $KDU_LIBDIR to /opt/kakadu/lib"; \
  cp "$KDU_LIBDIR"/* /opt/kakadu/lib/; \
  echo "Contents of /opt/kakadu/lib:"; \
  ls -l /opt/kakadu/lib

# ================================
# Stage 2: final Kakadu base image
# ================================
FROM ubuntu:24.04

# Bring in built Kakadu
COPY --from=build /opt/kakadu /opt/kakadu

# Make sure dynamic linker & JVM can see the libs
ENV LD_LIBRARY_PATH=/opt/kakadu/lib
ENV JAVA_TOOL_OPTIONS="-Djava.library.path=/opt/kakadu/lib"

# Just for debugging if you exec into it
WORKDIR /opt/kakadu
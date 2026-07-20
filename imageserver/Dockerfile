FROM ubuntu:24.04

ARG IMAGE_VERSION
ARG CANTALOUPE_VERSION=5.0.7
ARG CANTALOUPE_DIR=cantaloupe-${CANTALOUPE_VERSION}
ARG CANTALOUPE_JAR=cantaloupe-${CANTALOUPE_VERSION}.jar

LABEL org.opencontainers.image.title="OLDAP Imageserver"
LABEL org.opencontainers.image.description="Cantaloupe IIIF image server for OLDAP"
LABEL org.opencontainers.image.version="${IMAGE_VERSION}"

# Cantaloupe uses Java2D for pyramidal TIFF sources. Ruby is required by the
# authorization and source-resolution delegate.
RUN apt-get update -o Acquire::Retries=5 \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      openjdk-21-jre-headless \
      ruby \
 && rm -rf /var/lib/apt/lists/*

RUN gem install --no-document jwt net-http net-http-persistent

# Create app dirs
RUN mkdir -p /opt/iiif /data/images

# Copy Cantaloupe JAR + config from build context
COPY ${CANTALOUPE_DIR}/${CANTALOUPE_JAR} /opt/iiif/cantaloupe.jar
COPY cantaloupe-oldap/cantaloupe.properties /opt/iiif/cantaloupe.properties
COPY cantaloupe-oldap/delegates.rb /opt/iiif/delegates.rb

ENV CANTALOUPE_HOME=/opt/iiif
WORKDIR /opt/iiif

EXPOSE 8182

CMD ["java", \
     "-Dcantaloupe.config=/opt/iiif/cantaloupe.properties", \
     "-Xmx4g", \
     "-jar", "/opt/iiif/cantaloupe.jar"]

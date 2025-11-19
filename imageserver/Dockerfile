FROM lrosenth/kakadu-base:latest

ARG CANTALOUPE_DIR=cantaloupe-5.0.7
ARG CANTALOUPE_JAR=cantaloupe-5.0.7.jar

# Install Java runtime
RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Create app dirs
RUN mkdir -p /opt/iiif /data/images

# Copy Cantaloupe JAR + config from build context
COPY ${CANTALOUPE_DIR}/${CANTALOUPE_JAR} /opt/iiif/cantaloupe.jar
COPY cantaloupe-oldap/cantaloupe.properties /opt/iiif/cantaloupe.properties

# Optional hint for Cantaloupe itself
ENV kakadu.native.path=/opt/kakadu/lib/libkdu_v86R.so

ENV CANTALOUPE_HOME=/opt/iiif
WORKDIR /opt/iiif

EXPOSE 8182

CMD ["java", \
     "-Dcantaloupe.config=/opt/iiif/cantaloupe.properties", \
     "-Xmx4g", \
     "-jar", "/opt/iiif/cantaloupe.jar"]
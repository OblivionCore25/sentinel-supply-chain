# Stage 1: Build
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

# Copy parent POM and ALL module POMs (Maven validates the full reactor)
COPY pom.xml /workspace/pom.xml
COPY sentinel-common/pom.xml /workspace/sentinel-common/pom.xml
COPY sentinel-ingestion/pom.xml /workspace/sentinel-ingestion/pom.xml
COPY sentinel-analysis/pom.xml /workspace/sentinel-analysis/pom.xml
COPY sentinel-notification/pom.xml /workspace/sentinel-notification/pom.xml

# Create empty src dirs for modules we won't build (satisfies Maven reactor)
RUN mkdir -p /workspace/sentinel-analysis/src/main/java \
             /workspace/sentinel-notification/src/main/java

# Copy source code only for modules we build
COPY sentinel-common/src /workspace/sentinel-common/src
COPY sentinel-ingestion/src /workspace/sentinel-ingestion/src

# Build (skip tests for Docker build)
RUN apk add --no-cache maven && \
    cd /workspace && \
    mvn clean package -pl sentinel-common,sentinel-ingestion -am -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Add non-root user
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

COPY --from=build /workspace/sentinel-ingestion/target/*.jar app.jar

# Install curl for healthcheck
RUN apk add --no-cache curl

USER sentinel
EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]

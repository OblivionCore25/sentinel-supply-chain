# Stage 1: Build
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

# Copy parent POM and module POMs for dependency resolution
COPY ../pom.xml /workspace/pom.xml
COPY ../sentinel-common/pom.xml /workspace/sentinel-common/pom.xml
COPY pom.xml /workspace/sentinel-ingestion/pom.xml

# Copy source code
COPY ../sentinel-common/src /workspace/sentinel-common/src
COPY src /workspace/sentinel-ingestion/src

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

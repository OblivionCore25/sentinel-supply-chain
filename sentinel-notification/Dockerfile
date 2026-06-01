# Stage 1: Build
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

COPY ../pom.xml /workspace/pom.xml
COPY ../sentinel-common/pom.xml /workspace/sentinel-common/pom.xml
COPY pom.xml /workspace/sentinel-notification/pom.xml

COPY ../sentinel-common/src /workspace/sentinel-common/src
COPY src /workspace/sentinel-notification/src

RUN apk add --no-cache maven && \
    cd /workspace && \
    mvn clean package -pl sentinel-common,sentinel-notification -am -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

COPY --from=build /workspace/sentinel-notification/target/*.jar app.jar

RUN apk add --no-cache curl

USER sentinel
EXPOSE 8083

ENTRYPOINT ["java", "-jar", "app.jar"]

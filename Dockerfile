# ===========================
#  Auth Service Dockerfile
# ===========================

# Use official Java 21 image
FROM eclipse-temurin:21-jdk AS build

# Set working directory
WORKDIR /app

# Copy Maven wrapper & project files
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src

# Package the app (skip tests for faster build)
RUN ./mvnw clean package -DskipTests

# ===========================
#  Runtime image
# ===========================
FROM eclipse-temurin:21-jdk

WORKDIR /app

# Copy jar from builder
COPY --from=build /app/target/*.jar app.jar

# Copy Firebase config if present
# COPY src/main/resources/firebase-service-account.json /app/firebase-service-account.json

# Expose port
EXPOSE 8080

# Start Spring Boot
ENTRYPOINT ["java","-jar","/app/app.jar"]

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

# 🔥 IMPORTANT: make mvnw executable on Linux
RUN chmod +x mvnw

# Package the app (skip tests for faster build)
RUN ./mvnw clean package -DskipTests

# ===========================
#  Runtime image
# ===========================
FROM eclipse-temurin:21-jre  # You should use JRE, lighter image

WORKDIR /app

# Copy jar from builder
COPY --from=build /app/target/*.jar app.jar

# Expose Spring Boot port
EXPOSE 8085   # You wanted 8085, so change it

# Start Spring Boot
ENTRYPOINT ["java","-jar","/app/app.jar"]

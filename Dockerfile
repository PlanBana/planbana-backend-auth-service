# ===========================
#  Auth Service Dockerfile
# ===========================

# Use official Java 21 image
FROM eclipse-temurin:21-jdk AS build

WORKDIR /app

# Copy Maven wrapper & project files
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .
COPY src src

# Make mvnw executable
RUN chmod +x mvnw

# Build application
RUN ./mvnw clean package -DskipTests

# ===========================
#  Runtime image
# ===========================
# Using JRE is lighter than JDK
FROM eclipse-temurin:21-jre

WORKDIR /app

# Copy jar from builder
COPY --from=build /app/target/*.jar app.jar

# Expose port
EXPOSE 8085

ENTRYPOINT ["java","-jar","/app/app.jar"]

# Spring Boot Custom Authentication Provider

This project demonstrates how to implement a custom authentication provider in a Spring Boot application. By using a custom authentication provider, you can extend the default authentication mechanism provided by Spring Security and integrate your own authentication logic.

## Prerequisites

- Java Development Kit (JDK) 8 or later
- Spring Boot 2.x
- Maven build tool

## Getting Started

Follow these instructions to get a local copy of the project and run it on your machine.

1. Clone the repository:

   ```
   git clone https://github.com/dewantrie/springboot-custom-authentication-provider.git
   ```

2. Navigate to the project directory:

   ```
   cd springboot-custom-authentication-provider
   ```

3. Build the project using Maven or Gradle:

   - **Maven**:

     ```
     mvn clean package
     ```

4. Run the application:

   ```
   java -jar target/springboot-custom-authentication-provider.jar
   ```

5. The application should now be running locally on `http://localhost:8081`.

## Configuration

To configure and customize the authentication provider, modify the `CustomAuthenticationProvider` class in the project. This class implement the `AuthenticationProvider` provided by Spring Security and overrides the `authenticate` method to implement your own authentication logic.

In addition, you can modify the Spring Security configuration in the `SecurityConfig` class to specify which URLs require authentication and other security-related settings.

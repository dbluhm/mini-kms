# Mini KMS Service

## Overview

The Mini KMS (Key Management Service) is a lightweight, HTTP-based service designed for efficient and secure key management. Leveraging the robust Aries Askar library for key storage and management, this service provides an API for generating, retrieving, and deleting cryptographic keys. Built on the high-performance FastAPI framework, it offers rapid HTTP request handling and automatic API documentation.

This service is currently intended as a simple test stand in for more "complete" KMS solutions. The Askar store is held in a SQLite in-memory database; once the container shuts down, all generated keys will disappear.

The service supports a range of cryptographic operations, including key generation and signing, utilizing various algorithms as specified by the Aries Askar `KeyAlg`. All data is securely handled in-memory, ensuring fast access and enhanced security by avoiding disk-based storage vulnerabilities.

## Features

- **In-memory Key Storage**: Utilizes SQLite in-memory database for transient storage of cryptographic keys, ensuring fast access and improved security.
- **RESTful API**: Offers a simple and intuitive API for key management operations, including generating, retrieving, deleting keys, and signing messages.
- **Automatic API Documentation**: Leverages FastAPI's capability to auto-generate Swagger UI documentation, making it easy to test and integrate the service.
- **Docker Support**: Includes a Dockerfile for easy building and deployment, allowing the service to be containerized and run in any environment supporting Docker.

## Quick Start

### Prerequisites

- Docker installed on your system.

### Building and Running the Service

1. **Build the Docker image**:
    ```
    docker build -t mini-kms .
    ```

2. **Run the service**:
    ```
    docker run --rm -it -p 8080:80 mini-kms
    ```

This will start the Mini KMS service, binding it to port 8080 on your local machine. The service is now ready to accept API requests.

### Accessing the API Documentation

Once the service is running, you can access the API documentation and try out the API by navigating to `http://localhost:8080/docs` in your web browser. This page provides an interactive Swagger UI where you can execute API calls directly and view their responses.

## API Usage Examples

### Generate a Key

- **POST** `/key/generate`
    - **Request Body**: `{"alg": "Ed25519"}`
    - **Response**: Includes `kid` (Key ID), `jwk` (Public Key in JWK format), and `b58` (Public Key in Base58 encoding).

### Retrieve a Key

- **GET** `/key/{kid}`
    - Replace `{kid}` with the Key ID received from the generate call.
    - **Response**: Same as the generate key response.

### Delete a Key

- **DELETE** `/key/{kid}`
    - Replace `{kid}` with the Key ID of the key to delete.
    - **Response**: `{"message": "Key deleted"}`

### Sign a Message

- **POST** `/sign`
    - **Request Body**: `{"kid": "<Key ID>", "data": "<Base64Url encoded data>"}`
    - **Response**: `{"sig": "<Base64Url encoded signature>"}`

## Contributing

Please feel free to submit issues or pull requests on our GitHub repository. For major changes, please open an issue first to discuss what you would like to change.

## License

[Apache 2.0](https://choosealicense.com/licenses/apache-2.0/)

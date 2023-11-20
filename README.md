# Stylin-APIs-Backend

## Description

Stylin-APIs-Backend is a Python-based backend service utilizing Flask for server-side operations and MongoDB for database management. This project integrates SendGrid for email functionalities, making it a comprehensive solution for applications requiring backend services with email integration. It's designed to be robust, scalable, and easy to integrate into various front-end environments.

## Features

- **Flask Backend**: Utilizes Flask, a lightweight WSGI web application framework in Python, to handle backend requests and server-side logic.
- **MongoDB Database**: Employs MongoDB, a NoSQL database, for efficient data storage and retrieval.
- **SendGrid Integration**: Incorporates SendGrid for reliable email sending capabilities.
- **Data Testing**: Includes two datasets in JSON format for testing and validation purposes.

## Installation

To get the project up and running on your local machine for development and testing purposes, follow these steps:

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Semper8GitHub/Stylin-APIs-Backend.git
   cd Stylin-APIs-Backend
   ```

2. **Set Up a Virtual Environment (Optional)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Required Packages**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Variables**

   Set up necessary environment variables or add them to a .env file.

5. **Run the Application**
   ```bash
   flask run
   ```

## Usage

After installation, the application can be used as a backend service for web applications. Utilize the provided APIs to perform operations such as data retrieval, data manipulation, and email sending.


## Testing

The project includes JSON datasets for testing purposes. You can use these datasets to test the database operations and ensure the APIs are functioning as expected.

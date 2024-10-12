# ChatSphere
This application allows users to send and receive encrypted messages, including the option to upload images. It features a user-friendly interface for managing conversations and easily accessing message details.

# Encrypted Messaging Application

This is a secure messaging application built with Flask that enables users to send and receive encrypted messages, along with the ability to upload images. The app leverages RSA and AES encryption for secure communication.

## Features

- User authentication with signup and login functionality
- Send and receive encrypted messages
- Option to upload images along with messages
- View received messages in an organized inbox
- Delete messages as needed

## Technologies Used

- **Flask**: Web framework for building the application
- **Flask-SQLAlchemy**: ORM for database interactions
- **Flask-Login**: User session management
- **Cryptography**: For implementing RSA and AES encryption
- **SQLite**: Database for storing user and message data
- **Bootstrap**: For responsive front-end design

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ravirajbabasomane202/ChatSphere.git
   cd ChatSphere
2. Run this commands:
   ```bash
   pip install -r requirements.txt
   flask db init
   flask db migrate -m "Initial migration."
   flask db upgrade
   python app.py

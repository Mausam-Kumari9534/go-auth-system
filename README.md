# Go Auth System

A secure and modular Authentication System built using **Go, Gin, MongoDB, bcrypt and JWT**.

This project provides user registration, login, JWT-based authentication, protected routes, user deletion, forgot-password and reset-password functionality. APIs are tested using Postman and documented using OpenAPI.

---

## 📌 Project Overview

The main purpose of this project is to build a backend authentication system where users can:

- Create an account
- Login securely
- Receive a JWT authentication token
- Access protected APIs
- Delete a user account
- Request a password reset
- Reset their password using a secure reset token
- Access API documentation through OpenAPI

Passwords are never stored as plain text. They are hashed using **bcrypt** before being stored in MongoDB.

JWT is used to authenticate users when accessing protected APIs.

---

# 🚀 Features

## Authentication

- User Signup
- User Login
- Password hashing using bcrypt
- JWT token generation
- JWT authentication middleware
- Protected `/me` endpoint

## User Management

- Delete user using MongoDB ObjectID
- JWT protection for delete operation

## Password Management

- Forgot Password
- Secure random reset token generation
- SHA-256 hash of reset token stored in database
- Reset token expiry
- One-time-use reset token
- Reset password using bcrypt

## API & Development

- REST APIs
- Postman API testing
- OpenAPI 3.0.3 documentation
- MongoDB database
- Git and GitHub version control

---

# 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Go | Backend programming language |
| Gin | HTTP web framework |
| MongoDB | Database |
| MongoDB Go Driver | MongoDB connectivity |
| bcrypt | Password hashing |
| JWT | Authentication |
| Postman | API testing |
| OpenAPI | API documentation |
| Git | Version control |
| GitHub | Code hosting |

---

# 📁 Project Structure

```text
go-auth-system/
│
├── config/
│   └── database.go
│
├── handlers/
│   └── auth.go
│
├── middleware/
│   └── auth.go
│
├── models/
│   ├── user.go
│   └── password_reset.go
│
├── utils/
│   └── jwt.go
│
├── .env
├── .gitignore
├── go.mod
├── go.sum
├── main.go
├── openapi.json
└── README.md

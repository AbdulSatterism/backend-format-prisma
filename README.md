# Backend Format Mongoose - REST API Documentation

A robust and scalable backend application built with Express.js, TypeScript, MongoDB, and Mongoose. This application provides authentication, user management, and social login capabilities.

---

## 📋 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
  - [Authentication Routes](#authentication-routes)
  - [User Routes](#user-routes)
- [Response Format](#response-format)
- [Error Handling](#error-handling)

---

## ✨ Features

- 🔐 JWT-based authentication
- 👤 User management with role-based access control (RBAC)
- 📧 Email verification with OTP
- 🔑 Password reset functionality
- 🌐 Social authentication (Google, Facebook, Apple)
- 📁 File upload support
- 🛡️ Comprehensive error handling
- ✅ Request validation with Zod
- 📊 Query builder for filtering and pagination
- 🔄 Refresh token mechanism

---

## 🛠 Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Language:** TypeScript
- **Database:** MongoDB with Mongoose
- **Authentication:** JWT (JSON Web Tokens)
- **Validation:** Zod
- **File Upload:** Multer
- **Email Service:** Nodemailer
- **Logging:** Winston & Morgan

---

## 🚀 Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB
- npm or yarn

### Installation

```bash
# Clone the repository
git clone <repository-url>

# Navigate to project directory
cd backend-format-mongoose

# Install dependencies
npm install

# Set up environment variables
# Create a .env file and configure required variables

# Run development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

---

## 📚 API Documentation

Base URL: `http://localhost:YOUR_PORT`

---

## 🔐 Authentication Routes

### 1. User Registration

**Endpoint:** `POST /api/v1/user/create-user`

**Description:** Create a new user account. An OTP will be sent to the provided email for verification.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Please check your email to verify your account."
}
```

---

### 2. Verify Email

**Endpoint:** `POST /api/v1/auth/verify-email`

**Description:** Verify user email with OTP code sent during registration.

**Request Body:**

```json
{
  "email": "user@example.com",
  "one_time_code": 123456
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "message": "Your email has been successfully verified.",
  "data": {
    "user": {
      "_id": "user_id",
      "email": "user@example.com",
      "name": "User Name",
      "role": "USER",
      "image": "",
      "is_deleted": false,
      "verified": true,
      "created_at": "2025-01-01T00:00:00.000Z",
      "updated_at": "2025-01-01T00:00:00.000Z"
    },
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

---

### 3. Resend OTP

**Endpoint:** `POST /api/v1/auth/resend-otp`

**Description:** Resend verification OTP to user's email.

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Generate OTP and send successfully",
  "data": null
}
```

---

### 4. User Login

**Endpoint:** `POST /api/v1/auth/login`

**Description:** Login with email and password.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "message": "User login successfully",
  "data": {
    "user": {
      "_id": "user_id",
      "email": "user@example.com",
      "name": "User Name",
      "role": "USER",
      "image": "",
      "is_deleted": false,
      "verified": true,
      "created_at": "2025-01-01T00:00:00.000Z",
      "updated_at": "2025-01-01T00:00:00.000Z"
    },
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Note:** Refresh token is also set in HTTP-only cookie.

---

### 5. Google Login

**Endpoint:** `POST /api/v1/auth/google-login`

**Description:** Authenticate using Google OAuth.

**Request Body:**

```json
{
  "id_token": "google_id_token_here"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "User login successfully",
  "data": {
    "access_token": "jwt_token",
    "refresh_token": "jwt_refresh_token",
    "user": {
      "_id": "user_id",
      "email": "user@example.com",
      "name": "User Name",
      "google_id": "google_user_id",
      "role": "USER"
    }
  }
}
```

---

### 6. Facebook Login

**Endpoint:** `POST /api/v1/auth/facebook-login`

**Description:** Authenticate using Facebook OAuth.

**Request Body:**

```json
{
  "access_token": "facebook_access_token_here"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "User login successfully",
  "data": {
    "access_token": "jwt_token",
    "refresh_token": "jwt_refresh_token",
    "user": {
      "_id": "user_id",
      "email": "user@example.com",
      "name": "User Name",
      "facebook_id": "facebook_user_id",
      "role": "USER"
    }
  }
}
```

---

### 7. Apple Login

**Endpoint:** `POST /api/v1/auth/apple-login`

**Description:** Authenticate using Apple Sign-In.

**Request Body:**

```json
{
  "id_token": "apple_id_token_here"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "User login successfully via Apple",
  "data": {
    "access_token": "jwt_token",
    "refresh_token": "jwt_refresh_token",
    "user": {
      "_id": "user_id",
      "email": "user@example.com",
      "name": "User Name",
      "apple_id": "apple_user_id",
      "role": "USER"
    }
  }
}
```

---

### 8. Refresh Access Token

**Endpoint:** `POST /api/v1/auth/refresh-token`

**Description:** Generate a new access token using refresh token.

**Request Body:**

```json
{
  "token": "refresh_token_here"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Generate Access Token successfully",
  "data": {
    "access_token": "new_jwt_access_token"
  }
}
```

---

### 9. Access Token (from Cookie)

**Endpoint:** `POST /api/v1/auth/access-token`

**Description:** Get new access token from refresh token stored in cookie.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "new token provided",
  "data": {
    "access_token": "new_jwt_access_token"
  }
}
```

**Authentication Required:** Yes (USER, ADMIN)

---

### 10. Forgot Password

**Endpoint:** `POST /api/v1/auth/forgot-password`

**Description:** Request password reset OTP via email.

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Please check your email, we send a OTP!",
  "data": null
}
```

---

### 11. Reset Password

**Endpoint:** `POST /api/v1/auth/reset-password`

**Description:** Reset password using OTP token.

**Headers:**

```
Authorization: Bearer <otp_token_from_email>
```

**Request Body:**

```json
{
  "newPassword": "newPassword123"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Password reset successfully",
  "data": null
}
```

---

### 12. Change Password

**Endpoint:** `POST /api/v1/auth/change-password`

**Description:** Change password for authenticated user.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Request Body:**

```json
{
  "currentPassword": "oldPassword123",
  "newPassword": "newPassword123"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Password changed successfully"
}
```

**Authentication Required:** Yes (USER, ADMIN)

---

### 13. Delete Account

**Endpoint:** `DELETE /api/v1/auth/delete-account`

**Description:** Delete user account (soft delete).

**Headers:**

```
Authorization: Bearer <access_token>
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Account Deleted successfully",
  "data": null
}
```

**Authentication Required:** Yes (USER only)

---

## 👥 User Routes

### 1. Get User Profile

**Endpoint:** `GET /api/v1/user/profile`

**Description:** Get authenticated user's profile.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Profile data retrieved successfully",
  "data": {
    "_id": "user_id",
    "name": "User Name",
    "email": "user@example.com",
    "role": "USER",
    "gender": "MALE",
    "image": "image_url",
    "verified": true,
    "created_at": "2025-01-01T00:00:00.000Z",
    "updated_at": "2025-01-01T00:00:00.000Z"
  }
}
```

**Authentication Required:** Yes (USER, ADMIN)

---

### 2. Update Profile

**Endpoint:** `PATCH /api/v1/user/update-profile`

**Description:** Update user profile information.

**Headers:**

```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body (Form Data):**

```
name: "Updated Name"
image: <image_file> (optional, max 50MB)
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "Profile updated successfully",
  "data": {
    "_id": "user_id",
    "name": "Updated Name",
    "email": "user@example.com",
    "role": "USER",
    "image": "uploads/images/filename.jpg",
    "verified": true
  }
}
```

**Authentication Required:** Yes (USER, ADMIN)

---

### 3. Get All Users (Admin Only)

**Endpoint:** `GET /api/v1/user/all-user`

**Description:** Get all users with pagination and filtering.

**Headers:**

```
Authorization: Bearer <admin_access_token>
```

**Query Parameters:**

- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 10)
- `searchTerm` (optional): Search by name or email
- `sortBy` (optional): Sort field (e.g., created_at, name)
- `sortOrder` (optional): asc or desc

**Example Request:**

```
GET /api/v1/user/all-user?page=1&limit=10&sortBy=created_at&sortOrder=desc
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "all user retrieved successfully",
  "meta": {
    "page": 1,
    "limit": 10,
    "total_data_page": 3,
    "total_data": 25
  },
  "data": [
    {
      "_id": "user_id_1",
      "name": "User One",
      "email": "user1@example.com",
      "role": "USER",
      "verified": true,
      "created_at": "2025-01-01T00:00:00.000Z"
    },
    {
      "_id": "user_id_2",
      "name": "User Two",
      "email": "user2@example.com",
      "role": "USER",
      "verified": true,
      "created_at": "2025-01-02T00:00:00.000Z"
    }
  ]
}
```

**Authentication Required:** Yes (ADMIN only)

---

### 4. Get Single User (Admin Only)

**Endpoint:** `GET /api/v1/user/get-single-user/:id`

**Description:** Get specific user details by ID.

**Headers:**

```
Authorization: Bearer <admin_access_token>
```

**URL Parameters:**

- `id`: User ID

**Example Request:**

```
GET /api/v1/user/get-single-user/507f1f77bcf86cd799439011
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "User retrived successfully",
  "data": {
    "_id": "507f1f77bcf86cd799439011",
    "name": "John Doe",
    "email": "john@example.com",
    "role": "USER",
    "gender": "MALE",
    "image": "image_url",
    "verified": true,
    "created_at": "2025-01-01T00:00:00.000Z",
    "updated_at": "2025-01-01T00:00:00.000Z"
  }
}
```

**Authentication Required:** Yes (ADMIN only)

---

### 5. Search User by Phone

**Endpoint:** `GET /api/v1/user/user-search`

**Description:** Search for users by phone number.

**Headers:**

```
Authorization: Bearer <access_token>
```

**Query Parameters:**

- `searchTerm`: Phone number to search

**Example Request:**

```
GET /api/v1/user/user-search?searchTerm=1234567890
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "status_code": 200,
  "message": "get user by searching phone number",
  "data": [
    {
      "_id": "user_id",
      "name": "User Name",
      "email": "user@example.com",
      "phone": "1234567890",
      "role": "USER",
      "image": "image_url"
    }
  ]
}
```

**Authentication Required:** Yes (USER, ADMIN)

---

## 📤 Response Format

All API responses follow a consistent format:

### Success Response

```json
{
  "success": true,
  "status_code": 200,
  "message": "Operation successful message",
  "data": {} // or [] or null
}
```

### Success Response with Pagination

```json
{
  "success": true,
  "status_code": 200,
  "message": "Data retrieved successfully",
  "meta": {
    "page": 1,
    "limit": 10,
    "total_data_page": 5,
    "total_data": 50
  },
  "data": []
}
```

---

## ❌ Error Handling

### Error Response Format

```json
{
  "success": false,
  "status_code": 400,
  "message": "Error message",
  "errorMessages": [
    {
      "path": "field_name",
      "message": "Detailed error message"
    }
  ]
}
```

### Common Error Status Codes

| Status Code | Description                                             |
| ----------- | ------------------------------------------------------- |
| 400         | Bad Request - Invalid input data                        |
| 401         | Unauthorized - Invalid or missing authentication        |
| 403         | Forbidden - Insufficient permissions                    |
| 404         | Not Found - Resource doesn't exist                      |
| 409         | Conflict - Duplicate entry (e.g., email already exists) |
| 422         | Unprocessable Entity - Validation error                 |
| 500         | Internal Server Error - Server-side error               |

### Example Error Responses

**Validation Error (400):**

```json
{
  "success": false,
  "status_code": 400,
  "message": "Validation Error",
  "errorMessages": [
    {
      "path": "email",
      "message": "Invalid email address"
    },
    {
      "path": "password",
      "message": "Password must have at least 4 characters"
    }
  ]
}
```

**Unauthorized Error (401):**

```json
{
  "success": false,
  "status_code": 401,
  "message": "Unauthorized access",
  "errorMessages": [
    {
      "path": "",
      "message": "You are not authorized to access this resource"
    }
  ]
}
```

**Duplicate Error (409):**

```json
{
  "success": false,
  "status_code": 409,
  "message": "Email already exists!",
  "errorMessages": [
    {
      "path": "email",
      "message": "This email is already registered"
    }
  ]
}
```

---

## 🔒 Authentication

Most endpoints require authentication using JWT tokens. Include the access token in the Authorization header:

```
Authorization: Bearer <your_access_token>
```

### User Roles

- **USER**: Regular user with standard permissions
- **ADMIN**: Administrator with elevated permissions

---

## 📝 Notes

1. **OTP Expiration**: OTP codes expire after a certain period (configured in environment variables)
2. **Refresh Token**: Stored in HTTP-only cookies for security
3. **File Uploads**: Images are stored in `uploads/images/` directory
4. **Soft Delete**: User accounts are soft-deleted (is_deleted flag) rather than permanently removed
5. **Email Service**: Requires SMTP configuration in environment variables

---

## 🤝 Contributing

Feel free to submit issues and pull requests for improvements.

---

## 📄 License

ISC

---

## 👤 Author

Abdul Satter

---

**Happy Coding! 🚀**

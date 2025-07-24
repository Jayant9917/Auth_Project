# Auth Project Backend

## Overview
This backend provides authentication features including registration, login, logout, and email verification using OTP (One-Time Password). It uses JWT tokens for authentication and stores the token in HTTP-only cookies.

## Features
- User registration and login
- JWT-based authentication (token stored in cookies)
- Email verification with OTP
- Secure routes using middleware

## How Authentication Works
- On login, a JWT token is generated and sent as an HTTP-only cookie.
- The token contains the user's ID (`id` field in the payload).
- Protected routes use the `userAuth` middleware, which:
  - Reads the token from cookies
  - Decodes the token to extract the userId
  - Sets `req.body.userId` so controllers can use it

## Using `/send-verify-otp` Route
- **Endpoint:** `POST /api/auth/send-verify-otp`
- **Authentication:** Requires a valid login (token cookie must be present)
- **Request Body:** _No body required_
- **How it works:**
  - The backend extracts the userId from the token in cookies.
  - Sends a verification OTP to the user's email.

### Example Usage
1. **Register:**
   ```json
   POST /api/auth/register
   {
     "name": "Your Name",
     "email": "your@email.com",
     "password": "yourpassword"
   }
   ```
2. **Login:**
   ```json
   POST /api/auth/login
   {
     "email": "your@email.com",
     "password": "yourpassword"
   }
   ```
   - The response will set a `token` cookie.
3. **Send OTP:**
   ```
   POST /api/auth/send-verify-otp
   (No body required, just include the token cookie)
   ```

## Setup
1. Install dependencies:
   ```bash
   cd backend
   npm install
   ```
2. Set up your `.env` file with:
   - `MONGODB_URI` (your MongoDB connection string)
   - `JWT_SECRET` (your JWT secret)
   - `SENDER_EMAIL` (email for sending OTPs)
   - `SENDER_EMAIL_PASSWORD` (email password or app password)
3. Start the server:
   ```bash
   npm start
   ```

## Notes
- All protected routes require the `token` cookie to be present.
- The backend will handle extracting the userId from the token automatically.
- No sensitive information should be sent in the request body for protected routes.

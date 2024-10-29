# Simple Signup and Login System

This project is a simple signup and login-based system that authenticates users and redirects them to specific pages based on their roles. It uses JWT tokens stored in browser cookies to prevent CSRF attacks and MongoDB for user data storage.

## Features

- User Signup
- User Login
- Role-based redirection (Admin/User)
- JWT token-based authentication
- CSRF attack prevention
- MongoDB for user data storage

## Project Structure



## Installation

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd login
    ```

2. Install dependencies:
    ```sh
    npm install
    ```

3. Set up MongoDB:
    - Ensure MongoDB is running locally or update the connection string in [`src/config.js`](src/config.js) to point to your MongoDB instance.

4. Start the server:
    ```sh
    npm start
    ```

## Usage

1. Open your browser and navigate to `http://localhost:5000/signup` to create a new account.
2. After signing up, navigate to `http://localhost:5000/login` to log in.
3. Based on the role of the user, they will be redirected to either the admin page or the home page.
4. Note: In this, admins are created manually by updating the role of a user in the database.

## Code Overview

### Authentication Middleware

- [`authJWTandRole`](src/index.js): Middleware to authenticate JWT and check user roles.
- [`authenticateJWT`](src/index.js): Middleware to authenticate JWT without checking roles.

### Routes

- `/signup`: Renders the signup page and handles user registration.
- `/login`: Renders the login page and handles user authentication.
- `/admin`: Renders the admin page for users with the admin role.
- `/home`: Renders the home page for users with the user role.
- `/auth`: Endpoint to verify JWT token and return user data.

### Views

- [`login.ejs`](views/login.ejs): Login page.
- [`signup.ejs`](views/signup.ejs): Signup page.
- [`admin.ejs`](views/admin.ejs): Admin page.
- [`home.ejs`](views/home.ejs): Home page.

## Security

- JWT tokens are stored in HTTP-only cookies to prevent XSS attacks.
- CSRF attacks are mitigated by not allowing other websites to access the JWT token.

## Dependencies

- Express
- Mongoose
- Bcrypt
- Validator
- JSON Web Token (JWT)
- CORS

Happy Coding :)
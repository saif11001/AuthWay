# AuthWay

AuthWay is a **Node.js authentication and authorization API** built with **Express.js** and **MongoDB (Mongoose)**.  
It provides secure user authentication, JWT-based authorization, and role management for scalable applications.  

---

## Features
- User registration and login system.  
- JWT-based authentication with refresh token support.  
- Password hashing using **bcrypt**.  
- Role-based access control (Admin, User).  
- Secure environment configuration using **dotenv**.  
- Input validation with **express-validator**.  

---

## Tech Stack
- **Backend:** Node.js, Express.js  
- **Database:** MongoDB + Mongoose  
- **Authentication:** JWT, bcrypt  
- **Validation:** express-validator  
- **Other Tools:** dotenv, nodemon  

---

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/YourUsername/AuthWay.git
   cd AuthWay

2. Install dependencies:
   ```bash
   npm install

3. Create a .env file in the root directory and add the following:
   ```bash
   PORT=5000
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_secret_key

4. Start the server:
   ```bash
   npm start

---

## API Endpoints (Examples)

### Auth

- POST /api/auth/register → Register a new user.
- POST /api/auth/login → Login user and return token.
- POST /api/auth/logout → Logout user and invalidate refresh token.

### Users

- GET /api/users/me → Get current logged-in user.
- PATCH /api/users/update → Update user info.
- DELETE /api/users/delete → Delete user account.
- GET /api/users/:id (Admin only) → Get user by ID.

---

## Future Improvements

- Add 2FA (Two-Factor Authentication).
- Add email verification system.
- Build a frontend with React/Next.js.
- Admin dashboard to manage users.

## Author

Saif Eldeen Sobhi

LinkedIn
https://www.linkedin.com/in/saif-eldeen-sobhy/

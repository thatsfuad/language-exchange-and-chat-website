// const bcrypt = require("bcryptjs");
// const mysql = require("mysql");

// // MySQL Connection
// const db = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "admin",
//   database: "testdb",
// });

// const userService = {
//   // Register a new user
//   registerUser: async (newUser, callback) => {
//     try {
//       // Hash the password before saving it
//       const salt = await bcrypt.genSalt(10);
//       newUser.password = await bcrypt.hash(newUser.password, salt);

//       const sql = "INSERT INTO users SET ?";
//       db.query(sql, newUser, (err, result) => {
//         if (err) return callback(err);
//         return callback(null, result);
//       });
//     } catch (error) {
//       return callback(error);
//     }
//   },

//   // Log in user
//   loginUser: (email, password, callback) => {
//     const sql = `SELECT * FROM users WHERE email = ?`;

//     db.query(sql, [email], async (err, result) => {
//       if (err) return callback(err);

//       if (result.length === 0) {
//         return callback(null, null); // No user found
//       }

//       const user = result[0];

//       // Log the retrieved user and password to debug
//       console.log("User retrieved from DB:", user);
//       console.log("Password to compare:", user.password);

//       // Ensure password is a string (not null or undefined)
//       if (typeof user.password !== "string") {
//         return callback(new Error("Password is not a valid string"));
//       }

//       try {
//         // Compare the provided password with the hashed password
//         const isMatch = await bcrypt.compare(password, user.password);
//         if (!isMatch) {
//           return callback(null, null); // Password doesn't match
//         }

//         return callback(null, user);
//       } catch (error) {
//         return callback(error); // Handle bcrypt comparison errors
//       }
//     });
//   },

//   // Update user
//   updateUser: async (id, userData, callback) => {
//     try {
//       // If the password is being updated, hash the new password
//       if (userData.password) {
//         const salt = await bcrypt.genSalt(10);
//         userData.password = await bcrypt.hash(userData.password, salt);
//       }

//       const sql = `UPDATE users SET ? WHERE id = ?`;
//       db.query(sql, [userData, id], (err, result) => {
//         if (err) return callback(err);
//         return callback(null, result);
//       });
//     } catch (error) {
//       return callback(error);
//     }
//   },

//   // Get all users
//   getAllUsers: (callback) => {
//     const sql = "SELECT id, name, email FROM users"; // Avoid sending password
//     db.query(sql, (err, results) => {
//       if (err) return callback(err);
//       return callback(null, results);
//     });
//   },

//   // Get a single user by ID
//   getUserById: (id, callback) => {
//     const sql = "SELECT id, name, email FROM users WHERE id = ?";
//     db.query(sql, [id], (err, result) => {
//       if (err) return callback(err);
//       if (result.length === 0) return callback(null, null); // No user found
//       return callback(null, result[0]);
//     });
//   },
// };

// module.exports = userService;

const pool = require("../db/db"); // Import the MySQL connection
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userService = {
  // Register a new user
  registerUser: async (req, res) => {
    try {
      const { name, email, password } = req.body;
      if (!name || !email || !password) {
        return res.status(400).json({ message: "All fields are required" });
      }

      // Check if the email already exists
      const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
        email,
      ]);
      if (rows.length > 0) {
        return res.status(400).json({ message: "Email already exists" });
      }

      // Hash the password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Insert the new user
      const [result] = await pool.query(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        [name, email, hashedPassword]
      );

      return res.status(201).json({
        message: "User registered successfully",
        userId: result.insertId,
      });
    } catch (error) {
      return res.status(500).json({ message: "Error registering user", error });
    }
  },

  // Login user
  loginUser: async (req, res) => {
    try {
      const { email, password } = req.body;

      // Check if email and password are provided
      if (!email || !password) {
        return res
          .status(400)
          .json({ message: "Email and password are required" });
      }

      // Look up user by email
      const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
        email,
      ]);

      // Debugging: Check if any user is found
      if (rows.length === 0) {
        console.log("User not found for email:", email);
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const user = rows[0];

      // Compare the password using bcrypt
      const isMatch = await bcrypt.compare(password, user.password);

      // Debugging: Check if password comparison passes
      if (!isMatch) {
        console.log("Password does not match for user:", email);
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Generate JWT
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET, // This should now be correctly set
        { expiresIn: "1d" } // Token expiration time
      );
      console.log("Generated JWT token:", token);
      // Send the token as an HTTP-only cookie
      res.cookie("token", token, {
        httpOnly: true, // Prevents JavaScript access to the cookie
        secure: process.env.NODE_ENV === "production", // Only send over HTTPS in production
        maxAge: 24 * 60 * 60 * 1000, // 1 day expiration
        sameSite: "strict", // CSRF protection
      });

      return res.status(200).json({ message: "Login successful", user });
    } catch (error) {
      console.error("Error logging in:", error);
      return res.status(500).json({ message: "Error logging in", error });
    }
  },

  // Update user
  updateUser: async (req, res) => {
    try {
      const { id } = req.params;
      const { name, email, password } = req.body;

      // Look up user by ID
      const [rows] = await pool.query("SELECT * FROM users WHERE id = ?", [id]);
      if (rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const updatedData = {};
      if (name) updatedData.name = name;
      if (email) updatedData.email = email;

      // Hash the new password if provided
      if (password) {
        const salt = await bcrypt.genSalt(10);
        updatedData.password = await bcrypt.hash(password, salt);
      }

      // Update the user in the database
      const updateFields = Object.keys(updatedData)
        .map((key) => `${key} = ?`)
        .join(", ");
      const values = Object.values(updatedData);

      await pool.query(`UPDATE users SET ${updateFields} WHERE id = ?`, [
        ...values,
        id,
      ]);

      return res.status(200).json({ message: "User updated successfully" });
    } catch (error) {
      return res.status(500).json({ message: "Error updating user", error });
    }
  },

  // Get all users
  getAllUsers: async (req, res) => {
    try {
      const [users] = await pool.query("SELECT id, name, email FROM users");
      return res.status(200).json(users);
    } catch (error) {
      return res.status(500).json({ message: "Error retrieving users", error });
    }
  },

  // Get a single user by ID
  getUserById: async (req, res) => {
    try {
      const { id } = req.params;
      const [rows] = await pool.query(
        "SELECT id, name, email FROM users WHERE id = ?",
        [id]
      );
      if (rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      return res.status(200).json(rows[0]);
    } catch (error) {
      return res.status(500).json({ message: "Error retrieving user", error });
    }
  },

  // Request password reset
  requestPasswordReset: async (req, res) => {
    try {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({ message: "Email is required" });
      }

      // Look up user by email
      const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
        email,
      ]);
      if (rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const user = rows[0];

      // Generate reset token and expiry
      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetTokenExpiry = new Date(Date.now() + 3600000); // Token valid for 1 hour

      // Update user with reset token and expiry
      await pool.query(
        "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?",
        [resetToken, resetTokenExpiry, email]
      );

      // In a real-world scenario, you'd send this token via email
      return res
        .status(200)
        .json({ message: "Reset token generated", resetToken });
    } catch (error) {
      return res
        .status(500)
        .json({ message: "Error generating reset token", error });
    }
  },
  getLoggedInUser: async (req, res) => {
    try {
      // Assuming req.user is populated by verifyToken middleware and contains the email
      const userEmail = req.user.email;
      // Fetch the user from the database by email
      const [rows] = await pool.query(
        "SELECT id, name, email FROM users WHERE email = ?",
        [userEmail]
      );

      // Check if the user was found
      if (rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      // Send the user details as the response
      res.status(200).json(rows[0]);
    } catch (error) {
      console.error("Error fetching user data:", error);
      res.status(500).json({ message: "Error fetching user data", error });
    }
  },
  // Reset password using token
  resetPassword: async (req, res) => {
    try {
      const { resetToken, newPassword } = req.body;
      if (!resetToken || !newPassword) {
        return res
          .status(400)
          .json({ message: "Reset token and new password are required" });
      }

      // Look up user by reset token and check if it's expired
      const [rows] = await pool.query(
        "SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()",
        [resetToken]
      );
      if (rows.length === 0) {
        return res
          .status(400)
          .json({ message: "Invalid or expired reset token" });
      }

      const user = rows[0];

      // Hash the new password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      // Update user's password and clear reset token
      await pool.query(
        "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
        [hashedPassword, user.id]
      );

      return res.status(200).json({ message: "Password reset successfully" });
    } catch (error) {
      return res
        .status(500)
        .json({ message: "Error resetting password", error });
    }
  },
};

module.exports = userService;

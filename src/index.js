const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const collection = require('./config');
const validator = require('validator');
const jwt = require('jsonwebtoken');
// const cookieParser = require('cookie-parser');
// const { log } = require('console');
// Import CORS module to restrict access to the server by other domains
const cors = require('cors');
// const csrf = require('csurf');
const app = express();

// While giving the token to user, any other wesbite can't access the token and even can't perform CSRF attack
// app.use(cors({ origin: 'http://localhost:5000', credentials: true }));

// The above line of code allows the server to accept requests from the specified origin (http://localhost:5000) and allows credentials to be sent with the request. This is useful for allowing the client to send cookies with the request.

// Using a predefined secret key for JWT token
const secretKey = "harry's_secret"; // This should be stored in a secure environment

// convert data into json
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Set up csrf protection
// const csrfProtection = csrf({ cookie: true });

// Middleware to validate email
const emailValidator = (req, res, next) => {
  const email = req.body.email;

  if (!validator.isEmail(email)) {
    return res.status(400).send('Invalid email format');
  }

  next(); // Proceed to the next middleware/route
};
// const authenticateJWT = (req, res, next) => {
//   const token = req.headers.Authorization?.split(' ')[1];
//   if (!token) {
//       return res.status(403).send("Access denied. No token provided.");
//   }
//   try {
//       const decoded = jwt.verify(token, secretKey);
//       // log the decoded token to the console
//       console.log("Decoded token: ", decoded);
//       req.user = decoded; // Attach user info to request object
//       next();
//   } catch (err) {token
//       return res.status(403).send("Invalid token");
//   }
// };

const authJWTandRole = (role) => {
  return (req, res, next) => {
    console.log("Request headers: ", req.headers);
    console.log("Authenticating....")
    /*
    Format of Cookie in Header: 
    cookie: 'token=<token_string>
    */

    // Retrieve the cookie header
    const cookieHeader = req.headers.cookie;

    // Extract the token from the cookie if it exists
    const token = cookieHeader?.split('; ').find(row => row.startsWith('token='))?.split('=')[1];

    // Check if token exists in the cookie
    if (!token) {
      return res.status(403).send("Access denied. No token provided.");
    }

    try {
      // Verify and decode the token
      const decoded = jwt.verify(token, secretKey);

      // Log the decoded token to the console
      console.log("Decoded token: ", decoded);

      // Check if the role is the same as the role in the token
      if (role && role !== decoded.role) {
        return res.status(403).send("Unauthorized access");
      }

      // Attach user info to request object
      req.user = decoded;
      console.log("Token Validated")
      next(); // Continue to the next middleware or route handler
    } catch (err) {
      return res.status(403).send("Invalid token");
    }
  };
};

// A same middleware that only validates the token and does not check the role
const authenticateJWT = (req, res, next) => {
  console.log("Request headers: ", req.headers);
  console.log("Authenticating....")
  /*
  Format of Cookie in Header
  cookie: '
  token=<token
  string>
  */

  // Retrieve the cookie header
  const cookieHeader = req.headers.cookie;
  
  // Extract the token from the cookie if it exists
  const token = cookieHeader?.split('; ').find(row => row.startsWith('token='))?.split('=')[1];

  // Check if token exists in the cookie
  if (!token) {
    return res.status(403).send("Access denied. No token provided.");
  }

  try {
    // Verify and decode the token
    const decoded = jwt.verify(token, secretKey);

    // Log the decoded token to the console
    console.log("Decoded token: ", decoded);

    // Attach user info to request object
    req.user = decoded;
    console.log("Token Validated")
    next(); // Continue to the next middleware or route handler
  }
  catch (err) {
    return res.status(403).send("Invalid token");
  }
};

// use EJS view engine
app.set('view engine', 'ejs')

// static file
app.use(express.static("public"));

app.post("/auth", authenticateJWT, (req, res) => {
  const user = req.user
  console.log(user);

  // res.json({user})
  res.status(200).json({ user });
})

app.get("/login", (req, res) => {
  console.log("Redndering Login...");
  
  res.render("login")
});

// On logout remove the token from the cookie and redirect to login page
app.post("/logout", (req, res) => {
  res.clearCookie('token');
  // res.redirect("/login");
  // return status 200
  res.status(200).send("Logged out successfully");
});

app.get("/signup", (req, res) => {
  res.render("signup")
});

app.get("/admin", authJWTandRole("admin"), (req, res) => {
  console.log("Redndering Admin...");
  res.render("admin")
  // res.render('admin', { csrfToken: req.csrfToken() });
});

app.get("/home", authJWTandRole("user"), (req, res) => {
  console.log("Redndering Home...");
  res.render("home")
});

// Register User
// Signup route
app.post("/signup", emailValidator, async (req, res) => {
  try {
    // Create user data from request body
    const data = {
      name: req.body.username,
      email: req.body.email,
      password: req.body.password,
      role: "user"
    };

    // exist user
    const existuser = await collection.findOne({ email: data.email });

    if (existuser != null) {
      // res.send("User already exist");
      // Response with suitable code
      return res.status(409).send("User already exists"); // 409 means conflict
    } else {
      // hash the password
      const hashpasword = await bcrypt.hash(data.password, 10);
      data.password = hashpasword;

      // Insert user data into the collection
      // const userdata = await collection.insertMany(data);
      console.log(data);
      
      // const userdata = await collection.insertOne(data);
      

      //
      // Create a new instance of the collection model
      const newUser = new collection(data);
      
      // Use .save() to insert a single document
      await newUser.save();

      // use insertMany
      // const userdata = await collection.insertMany(data);
      res.redirect("/login");
    }
  }
  catch (error) {
    console.error(error);
    res.status(500).json({
      message: 'An error occurred while signing up the user',
      error: error.message
    });
  }
});

// login user
app.post("/login", async (req, res) => {
  try {
    // Find user by email
    // console.log("Request body: ", req.headers);  
    const user = await collection.findOne({ email: req.body.email });
    // console.log("User from login: ", user);

    // Check if user exists
    if (!user) {
      return res.status(404).send("User not found"); // User not found
    }
    // password from request body
    // console.log("Password from request: ", req.body.password);

    // Check if the password matches
    const passwordMatch = await bcrypt.compare(req.body.password, user.password);

    if (passwordMatch) {
      // Check the user's role
      const role = user.role; // Assuming `role` is stored in the user's document in MongoDB

      // If password matched, generate JWT token and send that token to user otherwise a suitable response
      const token = jwt.sign({ email: user.email, role: user.role }, secretKey);
      // console.log("Token from login: ", token);
      // res.status(200).json({ token });

      // Return token in the cookie with security
      res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
      // sameSite: 'Strict' can be used too
      console.log(role)

      // Redirect to page according to role

      if (role === "user") {
        console.log("Req is from user")
        return res.redirect("/home"); // Render home page for normal users
      } else if (role === "admin") {
        console.log("Req is from admin")
        return res.redirect("/admin"); // Render admin page for admin users
      } else {
        return res.status(403).send("Unauthorized access"); // If role is something unexpected
      }

    } else {
      return res.status(401).send("Wrong password"); // Wrong password
    }
  } catch (error) {
    console.error("Error during login:", error); // Log the error for debugging
    return res.status(500).send("An error occurred while logging in"); // General error message
  }
});



const port = 5000;
app.listen(port, () => {
  console.log(`Server started on port number: ${port}`);

});
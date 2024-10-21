const express = require("express");
const cookieParser = require("cookie-parser");
const authRoutes = require("./routes/authRoutes");
const cors = require("cors"); // Import CORS

const app = express();

// Middleware CORS
app.use(
  cors({
    origin: "*",
  })
);

// Middleware untuk parsing body dan cookies
app.use(express.json());
app.use(cookieParser());

// Routes
app.use("/api/auth", authRoutes);

module.exports = app;

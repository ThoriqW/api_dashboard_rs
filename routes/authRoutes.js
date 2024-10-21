const express = require("express");
const { login } = require("../controllers/authControllers");
const router = express.Router();

// Route untuk login
router.post("/login", login);

module.exports = router;

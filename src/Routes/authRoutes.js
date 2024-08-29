const {
  signup,
  login,
  forgotPassword,
  verifyOtp,
  resetPassword,
  protect,
} = require("../Controllers/authController");

const express = require("express");

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/forgotPassword", forgotPassword);
router.post("/verifyOtp", verifyOtp);
router.post("/resetPassword", protect, resetPassword);

module.exports = router;

const User = require("../Model/userModel");
const { promisify } = require("util");
const { catchAsync } = require("../Utils/catchAsync");
const jwt = require("jsonwebtoken");
const AppError = require("../Utils/appError");
const { sendResetOtp } = require("../Utils/email");
const bcrypt = require("bcryptjs");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  const expiresInDays = Number(process.env.JWT_COOKIES_EXPIRES_IN) || 7; // Default to 7 days if not set

  const cookieOptions = {
    expires: new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === "production") cookieOptions.secure = true;

  res.cookie("jwt", token, cookieOptions);

  // Remove password from the output
  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

const signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    fullname: req.body.fullname,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    mobileNumber: req.body.mobileNumber,
  });
  createSendToken(newUser, 201, res);
});

const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(
      new AppError("Please provide a valid email amd password!", 400)
    );
  }

  const user = await User.findOne({ email }).select("+password");
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }
  createSendToken(user, 200, res);
});

const protect = catchAsync(async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return next(
      new AppError("You are not logged in! please login to get access", 401)
    );
  }

  //verify token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const freshUser = await User.findById(decoded.id);
  if (!freshUser) {
    return next(
      new AppError("User belonging to this token no longer exits.", 401)
    );
  }

  // if (freshUser.changedPasswordAfter(decoded.iat)) {
  //   return next(
  //     new AppError("User recently changed password! please log in again.", 401)
  //   );
  // }

  req.user = freshUser;
  next();
});

const generateOtp = () => {
  return Math.floor(10000 + Math.random() * 90000).toString();
};

const forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError("No user with the email address", 404));
  }
  const otp = generateOtp();
  user.passwordResetOtp = otp;
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  await user.save({ validateBeforeSave: false });

  sendResetOtp(user.email, otp);

  res.status(200).json({
    status: "success",
    message: "OTP sent to email",
  });
});

const verifyOtp = catchAsync(async (req, res, next) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return next(new AppError("please provide the OTP", 400));
  }
  const user = await User.findOne({ email });
  console.log(user);
  if (!user) {
    return next(new AppError("User not found", 404));
  }

  if (
    !user ||
    user.passwordResetOtp !== otp ||
    user.passwordResetExpires < Date.now()
  ) {
    return next(new AppError("Invalid OTP or OTP has expired", 400));
  }
  // Clear OTP and expiration after successful verification
  user.passwordResetOtp = undefined;
  user.passwordResetExpires = undefined;
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: "success",
    message: "OTP verified. You can now reset your password.",
  });
});

const resetPassword = catchAsync(async (req, res, next) => {
  const { password, passwordConfirm } = req.body;

  if (password !== passwordConfirm) {
    return res
      .status(400)
      .json({ status: "error", message: "Passwords do not match" });
  }

  // Since the `protect` middleware was run before this, the user info will be available on `req.user`
  const user = req.user;

  if (!user) {
    return res.status(404).json({ status: "error", message: "User not found" });
  }

  user.password = await bcrypt.hash(password, 12); // Encrypt the new password
  await user.save({ validateBeforeSave: false });

  createSendToken(user, 200, res);
});

module.exports = {
  signup,
  login,
  protect,
  forgotPassword,
  verifyOtp,
  resetPassword,
};

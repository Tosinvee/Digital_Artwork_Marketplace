const User = require("../Model/userModel");
const { promisify } = require("util");
const { catchAsync } = require("../Utils/catchAsync");
const jwt = require("jsonwebtoken");
const AppError = require("../Utils/appError");
const { sendResetOtp } = require("../Utils/email");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

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
    message,
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
      new AppError("Please provide a valid email amd password!"),
      400
    );
  }

  const user = await User.findOne({ email }).select("+password");
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password"), 401);
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

const forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError("No user with the email address", 404));
  }
  const resetOtp = user.createPasswordResetOtp();
  await user.save({ validateBeforeSave: false });
  try {
    sendResetOtp(user.email, resetOtp);

    res.status(200).json({
      status: "success",
      message: "OTP sent to email",
    });
  } catch (error) {
    user.passwordResetOtp = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError("There was an error ending the email. Try again later!"),
      500
    );
  }
});

const verifyOtp = catchAsync(async (req, res, next) => {
  const otp = req.body.otp;

  if (!otp) {
    return next(new AppError("OTP is missing or invalid", 400));
  }

  console.log("Received OTP:", otp);

  const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

  const user = await User.findOne({
    passwordResetOtp: hashedOtp,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }

  user.passwordResetOtp = undefined;
  user.passwordResetExpires = undefined;
  await user.save({ validateBeforeSave: false });

  createSendToken(200, res, "OTP verified. You can now reset your password.");
});

const resetPassword = catchAsync(async (req, res, next) => {
  const { password, passwordConfirm } = req.body;

  if (!password || !passwordConfirm) {
    return next(new AppError("Please provide all required fields", 400));
  }

  if (password !== passwordConfirm) {
    return next(new AppError("passwords do not match ", 400));
  }

  const user = req.user;
  user.password = password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();

  res.status(200).json({
    status: "success",
    message: "Password has been reset successfully",
  });
});

module.exports = {
  signup,
  login,
  protect,
  forgotPassword,
  verifyOtp,
  resetPassword,
};

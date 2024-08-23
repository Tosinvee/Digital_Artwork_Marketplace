const mongoose = require("mongoose");
const validator = require("validator");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const userSchema = mongoose.Schema(
  {
    fullname: {
      type: String,
      required: [true, "User must provide a fullname"],
    },
    email: {
      type: String,
      unique: true,
      required: [true, "User must provide an email"],
      lowercase: true,
      validate: [validator.isEmail, "please provide a valid email"],
    },

    password: {
      type: String,
      required: [true, "please provide a password"],
      minLength: 8,
      select: false,
    },

    passwordConfirm: {
      type: String,
      required: [true, "please confirm your password"],
      validate: {
        validator: function (el) {
          return el === this.password; //to validate that password and confirm password are the same
        },
        message: "password are the same with passwordConfirm",
      },
    },
    mobileNumber: {
      type: String,
      default: null,
      validate: {
        validator: function (value) {
          return !value || validator.isMobilePhone(value);
        },
        message: "Please provide a valid mobile number",
      },
    },
    passwordResetOtp: String,
    passwordResetExpires: Date,
  },
  { timestamps: true }
);
userSchema.index({ email: 1 }, { unique: true });

userSchema.pre("save", async function (next) {
  if (this.isModified("password") && this.password !== null) {
    this.password = await bcrypt.hash(this.password, 12);
  }

  this.passwordConfirm = undefined;
  next();
});

// Method to check if the provided password matches the hashed password
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

//password reset token
userSchema.methods.createPasswordResetToken = async function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  console.log({ resetToken }, this.passwordResetToken);

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model("User", userSchema);

module.exports = User;

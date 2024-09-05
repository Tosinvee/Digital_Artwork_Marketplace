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
    passwordChangedAt: Date,
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
});

//TO Change password
userSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Method to check if the provided password matches the hashed password
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changePasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTImestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    // return true if the time the token was issued is less than the time the password was created or changed
    return JWTTimestamp < changedTImestamp;
  }
  return false;
};
//password reset token
userSchema.methods.createPasswordResetOtp = function () {
  const resetOtp = Math.floor(10000 + Math.random() * 90000).toString();

  this.passwordResetOtp = crypto
    .createHash("sha256")
    .update(resetOtp)
    .digest("hex");

  console.log({ resetOtp }, this.passwordResetOtp);

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetOtp;
};

const User = mongoose.model("User", userSchema);

module.exports = User;

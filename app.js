const express = require("express");
const { default: mongoose } = require("mongoose");
require("dotenv").config();
const authRouter = require("./src/Routes/authRoutes");
const morgan = require("morgan");
const cors = require("cors");
const AppError = require("./src/Utils/appError");
const globalError = require("./src/Controllers/errorController");
const app = express();

if ((process.env.NODE_ENV = "development")) app.use(morgan("dev"));
app.use(express.json());

const corsOptions = {
  origin: "*", // Allow all origins
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));

app.use("/auth", authRouter);

app.use("*", (req, res, next) => {
  next(new AppError(`can't find this ${req.originalUrl} on this server`));
});

app.use(globalError);

module.exports = app;

require("dotenv").config();
const app = require("./app");
const mongoose = require("mongoose");

const uri = process.env.DATABASE_URL;

mongoose.connect(uri);

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

port = 5050;
app.listen(port, () => {
  console.log(`server listening on ${port}`);
});

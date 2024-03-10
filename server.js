const express = require("express");
const mongoose = require("mongoose");
const categoryRoute=require("./routes/category");
const userRoute = require("./routes/user");
const userProfileRoute=require("./routes/userprofile");
const orderRoute=require("./routes/order");
const app = express();
const cors = require("cors");

app.use(express.json());
app.use(cors());

// Routes
app.use("",userProfileRoute);
app.use("", userRoute);
app.use("",categoryRoute);
app.use("",orderRoute);

// MongoDB connection URL
const MONGODB_URI = "mongodb://localhost:27017/store"; // Update with your MongoDB URI

require("./productdb");
// Connect to MongoDB using promises
mongoose
  .connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error.message);
  });

// Start the server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});

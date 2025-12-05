const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();
const port = process.env.port || 5000
//middleware
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("homedish-hub server running");
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});

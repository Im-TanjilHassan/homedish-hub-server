const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const jwt = require("jsonwebtoken")

const app = express();
const port = process.env.port || 5000
//middleware
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
app.use(express.json());

const uri =process.env.MONGO_URI

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect();
    console.log("mongo connected successfully");

    const db = client.db("homeDishDB");
    const userCollection = db.collection("users")

    //register user
    app.post("/registration", async (req, res) => {
      const user = req.body;

      const userExists = await userCollection.findOne({ email: user.email });

      if (userExists) {
        return res.status(409).json({
          message: "user already exists",
        });
      }

      const newUser = {
        ...user,
        role: "user",
        status: "active",
      };

      const result = await userCollection.insertOne(newUser);

      res.send(result);
    });

  
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("homedish-hub server running");
});

app.listen(port, () => {
  console.log("Server running on port 5000");
});

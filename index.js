const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const port = process.env.port || 5000;
//middleware
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

//token middleware
const tokenVerify = (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({
      message: "Unauthorized",
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "invalid token" });

    req.user = decoded;
    next();
  });
};

const uri = process.env.MONGO_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    console.log("mongo connected successfully");

    const db = client.db("homeDishDB");
    const userCollection = db.collection("users");

    //register user
    app.post("/registration", async (req, res) => {
      try {
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
      } catch (err) {
        console.log(err);
        res.status(500).json({
          message: "User Registration failed",
          error: err,
        });
      }
    });

    //login user with jwt token
    app.post("/login", async (req, res) => {
      try {
        const { email } = req.body;

        const userExists = await userCollection.findOne({ email });

        if (!userExists) {
          return res.status(404).json({
            message: "User not found",
          });
        }

        const tokenPayload = {
          uid: userExists.uid,
          email: userExists.email,
          role: userExists.role,
        };

        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
          expiresIn: "7d",
        });

        res.cookie("token", token, {
          httpOnly: true,
          secure: false,
          sameSite: "lax",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.send("login Successful");
      } catch (err) {
        console.log(err);
        res.status(500).json({
          message: "login failed",
          error: err,
        });
      }
    });

    //user profile
    app.get("/profile", tokenVerify, async (req, res) => {
      try {
        const email = req.decoded.email;

        const user = await userCollection.findOne({ email })
        
        if (!user) {
          return res.status(404).json({
            message: "user not found!"
          })
        }

        res.send(user)
        
      } catch (err) {
        console.log(err);
        res.status(500).json({
          message: "Failed to load profile"
        })
        
      }
    })
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

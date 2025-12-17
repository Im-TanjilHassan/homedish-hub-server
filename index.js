const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
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

//verify token middleware
const tokenVerify = (req, res, next) => {
  console.log("tokenVerify HIT");
  let token = null;

  console.log("Cookies:", req.cookies);
  console.log("Auth header:", req.headers.authorization);

  if (req.cookies?.token) {
    token = req.cookies.token;
    console.log("Token from cookie");
  }

  if (!token) {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
      console.log("Token from header");
    }
  }

  if (!token) {
    console.log("NO TOKEN FOUND");
    return res.status(401).json({
      message: "Unauthorized: no token",
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "invalid token" });
    }

    console.log("JWT VERIFIED:", decoded.email);
    req.decoded = decoded;
    next();
  });
};

//verify admin
const verifyAdmin = (userCollection) => {
  return async (req, res, next) => {
    const email = req.decoded?.email;
    if (!email) {
      return res.status(401).json({
        message: "Unauthorized: no emil in token",
      });
    }

    const user = await userCollection.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "user not found",
      });
    }

    if (!user || user.role !== "admin") {
      return res.status(403).json({
        message: "Forbidden: Admin only",
      });
    }

    req.currentUser = user;
    next();
  };
};

//generate chefId
const generateChefId = async (userCollection) => {
  let chefId;
  let exists = true;

  while (exists) {
    const random = Math.floor(1000 + Math.random() * 9000);
    chefId = `chef-${random}`;

    const user = await userCollection.findOne({ chefId });
    if (!user) exists = false;
  }

  return chefId;
};

//verifyChef
const verifyChef = (userCollection) => {

  return async (req, res, next) => {
    console.log("VERIFY CHEF HIT");
    try {
      const email = req.decoded.email;
      console.log("DECODED EMAIL:", email);

      if (!email) {
        return res.status(401).send({ message: "Unauthorized access" });
      }

      const user = await userCollection.findOne({ email });
      console.log("USER FOUND:", user);

      // Role check
      if (!user || user.role !== "chef") {
        return res.status(403).send({ message: "forbidden" });
      }

      // Fraud check
      if (user.status === "fraud") {
        return res.status(403).send({ message: "Fraud chef access blocked" });
      }

      // useful data
      req.chefId = user.chefId;
      req.chefUser = user;

      next();
    } catch (error) {
      console.error("VERIFY CHEF ERROR:", error);
      res.status(500).send({ message: "Chef verification failed" });
    }
  }
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
    //collections
    const userCollection = db.collection("users");
    const mealsCollection = db.collection("meals");

    //make admin
    async function makeAdmin() {
      const adminEmail = "tanjil@gmail.com";

      const existingUser = await userCollection.findOne({ email: adminEmail });

      if (!existingUser) {
        await userCollection.insertOne({
          name: "Admin User",
          email: adminEmail,
          role: "admin",
          status: "active",
        });

        console.log("admin created", adminEmail);
      } else {
        if (existingUser.role !== "admin") {
          await userCollection.updateOne(
            { email: adminEmail },
            { $set: { role: "admin" } }
          );
          console.log("user promoted to admin", adminEmail);
        } else {
          console.log("Admin already exists", adminEmail);
        }
      }
    }

    await makeAdmin();

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
          path: "/",
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

        const user = await userCollection.findOne(
          { email },
          { projection: { name: 1, email: 1, role: 1, status: 1, address: 1, chefId:1 } }
        );

        if (!user) {
          return res.status(404).json({
            message: "user not found!",
          });
        }

        res.send(user);
      } catch (err) {
        console.log(err);
        res.status(500).json({
          message: "Failed to load profile",
        });
      }
    });

    //user logout
    app.post("/logout", (req, res) => {
      try {
        res
          .clearCookie("token", {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
          })
          .status(200)
          .json({ success: true, message: "Logged out successfully" });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Logout failed",
        });
      }
    });

    //all users
    app.get(
      "/admin/allUsers",
      tokenVerify,
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          const users = await userCollection.find().toArray();

          res.send({
            success: true,
            count: users.length,
            data: users,
          });
        } catch (err) {
          console.log(err);
          res.status(500).json({
            message: "failed to fetch users",
          });
        }
      }
    );

    //make user fraud
    app.patch(
      "/admin/users/:id/fraud",
      tokenVerify,
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          const { id } = req.params;

          const user = await userCollection.findOne({
            _id: new ObjectId(id),
          });

          if (!user) {
            return res.status(404).json({
              success: false,
              message: "User not found",
            });
          }

          if (user.role === "admin") {
            return res.status(403).json({
              success: false,
              message: "Admin cannot be marked as fraud",
            });
          }

          if (user.status === "fraud") {
            return res.status(400).json({
              success: false,
              message: "User already marked as fraud",
            });
          }

          const result = await userCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: "fraud" } }
          );

          res.status(200).json({
            success: true,
            message: "User marked as fraud successfully",
            modifiedCount: result.modifiedCount,
          });
        } catch (error) {
          console.error("Make fraud error:", error);
          res.status(500).json({
            success: false,
            message: "Failed to update user status",
          });
        }
      }
    );

    //role request
    app.post("/chefRequest", tokenVerify, async (req, res) => {
      try {
        const email = req.decoded.email;

        // Find user
        const user = await userCollection.findOne({ email });

        if (!user) {
          return res.status(404).json({
            message: "User not found",
          });
        }

        // Prevent duplicate requests
        if (user.role === "chef") {
          return res.status(400).json({
            message: "You are already a chef",
          });
        }

        if (user.role === "chef-pending") {
          return res.status(409).json({
            message: "Chef request already submitted",
          });
        }

        // Update role → chef-pending
        const result = await userCollection.updateOne(
          { email },
          {
            $set: {
              role: "chef-pending",
              chefRequestedAt: new Date(),
            },
          }
        );

        // Response
        res.status(200).json({
          message: "Chef request submitted successfully",
          result,
        });
      } catch (error) {
        console.log("Chef request error:", error);

        res.status(500).json({
          message: "Failed to submit chef request",
        });
      }
    });

    //get pending chef request
    app.get(
      "/chefRequests",
      tokenVerify,
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          const pendingChefs = await userCollection
            .find({ role: "chef-pending" })
            .project({
              name: 1,
              email: 1,
              image: 1,
              chefRequestedAt: 1,
              role: 1,
              address: 1,
            })
            .toArray();

          res.status(200).send(pendingChefs);
        } catch (err) {
          res.status(500).json({
            message: "Failed to load chef requests",
          });
        }
      }
    );

    //chef req approve
    app.patch(
      "/chefRequests/accept/:id",
      tokenVerify,
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          const userId = req.params.id;

          const user = await userCollection.findOne({
            _id: new ObjectId(userId),
          });

          if (!user || user.role !== "chef-pending") {
            return res.status(400).json({
              message: "Invalid chef request",
            });
          }

          const chefId = await generateChefId(userCollection);

          await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            {
              $set: {
                role: "chef",
                chefId,
                chefApprovedAt: new Date(),
              },
            }
          );

          res.status(200).json({
            message: "Chef approved successfully",
            chefId,
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({
            message: "Failed to approve chef request",
          });
        }
      }
    );

    //chef req reject
    app.patch(
      "/chefRequests/reject/:id",
      tokenVerify,
      verifyAdmin(userCollection),
      async (req, res) => {
        try {
          const { id } = req.params;

          const user = await userCollection.findOne({
            _id: new ObjectId(id),
          });

          if (!user) {
            return res.status(404).json({
              message: "User not found",
            });
          }

          if (user.role !== "chef-pending") {
            return res.status(400).json({
              message: "This user has no pending chef request",
            });
          }

          const result = await userCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: { role: "user" },
              $unset: { chefRequestedAt: "" },
            }
          );

          res.status(200).json({
            message: "Chef request rejected successfully",
            result,
          });
        } catch (error) {
          console.error("Reject chef request error:", error);

          res.status(500).json({
            message: "Failed to reject chef request",
          });
        }
      }
    );

    //create meal
    app.post("/meals", tokenVerify, verifyChef(userCollection), async (req, res) => {
      try {
        console.log("REQ BODY:", req.body);
        console.log("DECODED:", req.decoded);
        console.log("CHEF ID:", req.chefId);
        
      const {
        foodName,
        chefName,
        foodImage,
        price,
        ingredients,
        estimatedDeliveryTime,
        chefExperience,
      } = req.body;

        if (
          !foodName ||
          !foodImage ||
          !price ||
          !ingredients ||
          !estimatedDeliveryTime
        ) {
          return res.status(400).send({
            message: "Missing required meal fields",
          });
        }

        // price must be a number
        if (isNaN(price)) {
          return res.status(400).send({
            message: "Price must be a valid number",
          });
        }

        // ingredients must be an array
        const ingredientsArray = Array.isArray(ingredients)
          ? ingredients
          : ingredients
              .split(",")
              .map((i) => i.trim())
              .filter(Boolean);

        const newMeal = {
          foodName,
          chefName,
          foodImage,
          price: Number(price),
          ingredients: ingredientsArray,
          estimatedDeliveryTime,
          chefExperience: chefExperience,
          rating: 0,
          chefId: req.chefId,
          userEmail: req.decoded.email,
          createdAt: new Date(),
        };

        const result = await mealsCollection.insertOne(newMeal);

        res.send({
          success: true,
          insertedId: result.insertedId,
        });
      } catch (error) {
        console.error("CREATE MEAL ERROR:", error);
        res.status(500).send({ message: "Failed to create meal" });
      }
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

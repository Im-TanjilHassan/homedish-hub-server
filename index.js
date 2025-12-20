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
  // console.log("tokenVerify HIT");
  let token = null;

  // console.log("Cookies:", req.cookies);
  // console.log("Auth header:", req.headers.authorization);

  if (req.cookies?.token) {
    token = req.cookies.token;
    // console.log("Token from cookie");
  }

  if (!token) {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader?.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
      // console.log("Token from header");
    }
  }

  if (!token) {
    // console.log("NO TOKEN FOUND");
    return res.status(401).json({
      message: "Unauthorized: no token",
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "invalid token" });
    }

    // console.log("JWT VERIFIED:", decoded.email);
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
    // console.log("VERIFY CHEF HIT");
    try {
      const email = req.decoded.email;
      // console.log("DECODED EMAIL:", email);

      if (!email) {
        return res.status(401).send({ message: "Unauthorized access" });
      }

      const user = await userCollection.findOne({ email });
      // console.log("USER FOUND:", user);

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
      // console.error("VERIFY CHEF ERROR:", error);
      res.status(500).send({ message: "Chef verification failed" });
    }
  };
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
    const reviewsCollection = db.collection("reviews");
    const favoriteMealCollection = db.collection("favMeals");

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

    // USER RELATED ROUTES
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
          {
            projection: {
              name: 1,
              email: 1,
              role: 1,
              status: 1,
              address: 1,
              chefId: 1,
            },
          }
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

    // MEAL RELATED ROUTES
    //create meal
    app.post(
      "/meals",
      tokenVerify,
      verifyChef(userCollection),
      async (req, res) => {
        try {
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
          // console.error("CREATE MEAL ERROR:", error);
          res.status(500).send({ message: "Failed to create meal" });
        }
      }
    );

    //get all meal with sort
    app.get("/allMeals", async (req, res) => {
      try {
        const sort = req.query.sort;

        let sortOption = {};

        if (sort === "asc") {
          sortOption = { price: 1 };
        } else if (sort === "desc") {
          sortOption = { price: -1 };
        }

        const meals = await mealsCollection.find().sort(sortOption).toArray();

        res.send(meals);
      } catch (error) {
        res.status(500).send({
          message: "Failed to fetch meals",
          error: error.message,
        });
      }
    });

    //latest meal for home page
    app.get("/meals/home", async (req, res) => {
      try {
        const meals = await mealsCollection
          .find({})
          .sort({ createdAt: -1 })
          .limit(6)
          .project({
            foodName: 1,
            chefName: 1,
            foodImage: 1,
            price: 1,
            rating: 1,
          })
          .toArray();

        res.send(meals);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to load meals" });
      }
    });

    //get single meal data
    app.get("/meals/:id", async (req, res) => {
      try {
        const { id } = req.params;

        // Validate MongoDB ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid meal ID" });
        }

        const query = { _id: new ObjectId(id) };
        const meal = await mealsCollection.findOne(query);

        if (!meal) {
          return res.status(404).send({ message: "Meal not found" });
        }

        res.send(meal);
      } catch (error) {
        console.error("Error fetching meal:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    //get specific chef meal
    app.get(
      "/chef/meals",
      tokenVerify,
      verifyChef(userCollection),
      async (req, res) => {
        const chefId = req.chefId;

        const meals = await mealsCollection
          .find({ chefId })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(meals);
      }
    );

    //delete a meal
    app.delete(
      "/meals/:id",
      tokenVerify,
      verifyChef(userCollection),
      async (req, res) => {
        const mealId = req.params.id;
        const chefId = req.chefId;

        const result = await mealsCollection.deleteOne({
          _id: new ObjectId(mealId),
          chefId,
        });

        if (result.deletedCount === 0) {
          return res
            .status(404)
            .send({ message: "Meal not found or unauthorized" });
        }

        res.send({ success: true, message: "Meal deleted successfully" });
      }
    );

    //update a meal
    app.patch(
      "/meals/:id",
      tokenVerify,
      verifyChef(userCollection),
      async (req, res) => {
        const mealId = req.params.id;
        const chefId = req.chefId;
        const updatedData = req.body;

        const result = await mealsCollection.updateOne(
          { _id: new ObjectId(mealId), chefId },
          {
            $set: {
              ...updatedData,
              updatedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res
            .status(404)
            .send({ message: "Meal not found or unauthorized" });
        }

        res.send({ success: true, message: "Meal updated successfully" });
      }
    );

    // REVIEW RELATED ROUTES
    //post review
    app.post("/reviews", tokenVerify, async (req, res) => {
      try {
        const userEmail = req.decoded.email;

        const user = await userCollection.findOne({ email: userEmail });

        // Role validation
        if (!user || user.role !== "user") {
          return res.status(403).send({
            message: "Only normal users can submit reviews",
          });
        }
        const {
          foodId,
          reviewerName,
          reviewerImage,
          rating,
          comment,
          reviewerEmail,
        } = req.body;

        // Basic validation
        if (
          !foodId ||
          !ObjectId.isValid(foodId) ||
          !reviewerName ||
          !reviewerEmail ||
          !rating ||
          !comment
        ) {
          return res.status(400).send({ message: "Invalid review data" });
        }

        const review = {
          foodId: new ObjectId(foodId),
          reviewerName,
          reviewerEmail,
          reviewerImage,
          rating: Number(rating),
          comment,
          date: new Date(),
        };

        const result = await reviewsCollection.insertOne(review);

        res.send({
          success: true,
          insertedId: result.insertedId,
          message: "Review submitted successfully!",
        });
      } catch (error) {
        console.error("Error adding review:", error);
        res.status(500).send({ message: "Failed to submit review" });
      }
    });

    //get all review
    app.get("/allReview", async (req, res) => {
      try {
        const reviews = await reviewsCollection
          .find()
          .sort({ date: -1 })
          .toArray();
        res.send(reviews);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch reviews" });
      }
    });

    //get specific food review
    app.get("/reviews", async (req, res) => {
      try {
        const { foodId } = req.query;

        if (!foodId || !ObjectId.isValid(foodId)) {
          return res.status(400).send({ message: "Invalid foodId" });
        }

        const query = { foodId: new ObjectId(foodId) };

        const reviews = await reviewsCollection
          .find(query)
          .sort({ date: -1 })
          .toArray();

        res.send(reviews);
      } catch (error) {
        console.error("Error fetching reviews:", error);
        res.status(500).send({ message: "Failed to fetch reviews" });
      }
    });

    //my review
    app.get("/my-reviews", tokenVerify, async (req, res) => {
      const email = req.query.email;

      if (email !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden access" });
      }

      const reviews = await reviewsCollection
        .aggregate([
          {
            $match: { reviewerEmail: email },
          },
          {
            $addFields: {
              foodObjectId: { $toObjectId: "$foodId" },
            },
          },
          {
            $lookup: {
              from: "meals",
              localField: "foodObjectId",
              foreignField: "_id",
              as: "meal",
            },
          },
          {
            $unwind: "$meal",
          },
          {
            $project: {
              rating: 1,
              comment: 1,
              date: 1,
              foodName: "$meal.foodName",
            },
          },
          {
            $sort: { date: -1 },
          },
        ])
        .toArray();

      res.send(reviews);
    });

    //delete my review
    app.delete("/reviews/:id", tokenVerify, async (req, res) => {
      const reviewId = req.params.id;

      if (!ObjectId.isValid(reviewId)) {
        return res.status(400).send({ message: "Invalid review id" });
      }

      // Find the review first
      const review = await reviewsCollection.findOne({
        _id: new ObjectId(reviewId),
      });

      if (!review) {
        return res.status(404).send({ message: "Review not found" });
      }

      // Authorization check
      if (review.reviewerEmail !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden access" });
      }

      const foodId = review.foodId;

      // Delete the review
      await reviewsCollection.deleteOne({
        _id: new ObjectId(reviewId),
      });

      res.send({
        success: true,
        message: "Review deleted successfully",
      });
    });

    //edit my review
    app.patch("/reviews/:id", tokenVerify, async (req, res) => {
      const reviewId = req.params.id;
      const { rating, comment } = req.body;

      if (!ObjectId.isValid(reviewId)) {
        return res.status(400).send({ message: "Invalid review id" });
      }

      if (!rating || !comment) {
        return res
          .status(400)
          .send({ message: "Rating and comment are required" });
      }

      // Find the review
      const review = await reviewsCollection.findOne({
        _id: new ObjectId(reviewId),
      });

      if (!review) {
        return res.status(404).send({ message: "Review not found" });
      }

      //Authorization
      if (review.reviewerEmail !== req.decoded.email) {
        return res.status(403).send({ message: "Forbidden access" });
      }

      // Update review
      await reviewsCollection.updateOne(
        { _id: new ObjectId(reviewId) },
        {
          $set: {
            rating: Number(rating),
            comment,
            date: new Date(),
          },
        }
      );

      res.send({
        success: true,
        message: "Review updated successfully",
      });
    });

    // FAVORITE MEAL RELATED ROUTES
    // Add to Favorite
    app.post("/favorites", tokenVerify, async (req, res) => {
      try {
        const {
          mealId,
          mealImage,
          mealName,
          chefId,
          chefName,
          price,
          userEmail,
        } = req.body;

        // Security check
        if (req.decoded.email !== userEmail) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        // Required field validation
        if (!mealId || !userEmail) {
          return res.status(400).send({
            message: "mealId and userEmail are required",
          });
        }

        // Duplicate check
        const isExist = await favoriteMealCollection.findOne({
          mealId,
          userEmail,
        });

        if (isExist) {
          return res.status(409).send({
            message: "This meal is already in your favorites Collection",
          });
        }

        // Favorite document
        const favoriteMeal = {
          mealId,
          mealName,
          mealImage,
          chefId,
          chefName,
          price,
          userEmail,
          addedTime: new Date(),
        };

        // Insert
        const result = await favoriteMealCollection.insertOne(favoriteMeal);

        res.status(201).send({
          message: "Meal added to favorites successfully",
          insertedId: result.insertedId,
        });
      } catch (error) {
        res.status(500).send({
          message: "Failed to add favorite meal",
          error: error.message,
        });
      }
    });

    // Get Favorite Meals by user
    app.get("/favorites", tokenVerify, async (req, res) => {
      try {
        const email = req.query.email;

        // security check
        if (!req.decoded?.email) {
          return res.status(401).send({ message: "Unauthorized access" });
        }

        if (req.decoded.email !== email) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        const result = await favoriteMealCollection
          .find({ userEmail: email })
          .sort({ addedTime: -1 })
          .toArray();

        res.send(result);
      } catch (error) {
        res.status(500).send({
          message: "Failed to fetch favorite meals",
        });
      }
    });


    // Delete a favorite meal
    app.delete("/favorites/:id", tokenVerify, async (req, res) => {
      try {
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid favorite ID" });
        }

        // find favorite first
        const favorite = await favoriteMealCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!favorite) {
          return res.status(404).send({ message: "Favorite not found" });
        }

        // security check
        if (favorite.userEmail !== req.decoded?.email) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        // delete
        const result = await favoriteMealCollection.deleteOne({
          _id: new ObjectId(id),
        });

        res.send({
          message: "Meal removed from favorites successfully",
          deletedCount: result.deletedCount,
        });
      } catch (error) {
        console.error("Delete Favorite Error:", error);
        res.status(500).send({ message: "Internal Server Error" });
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

const bcrypt = require("bcryptjs");
var express = require("express");
const { uuid } = require("uuidv4");
var router = express.Router();
const jwt = require("jsonwebtoken");
const { db } = require("../mongo");

let user = {};

//////////////////////////////////////////////////////

/* GET users listing. */
router.get("/", function (req, res, next) {
  res.send("respond with a resource");
});

//////////////////////////////////////////////////////////

router.post("/register", async function (req, res, next) {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const saltRounds = 5;
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);

    user = {
      email,
      password: hash,
      id: uuid(),
    };

    const insertUser = db().collection("users").insertOne(user);

    res.json({
      success: true,
    });
  } catch (err) {
    res.json({
      success: false,
      error: err.toString(),
    });
  }
});

///////////////////////////////////////////////////////////////

router.post("/login", async (req, res) => {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const resultUser = await db().collection("users").findOne({
      email: email,
    });

    if (!resultUser) {
      res
        .json({
          success: false,
          message: "Could not find user.",
        })
        .status(204);
      return;
    }

    const userType = email.includes("codeimmersives.com") ? "admin" : "user";
    const userData = {
      date: new Date(),
      userID: resultUser.id,
      scope: userType,
    };
    const exp = Math.floor(Date.now() / 1000) + 60 * 60;
    const payload = {
      userData,
      exp,
    };
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(payload, jwtSecretKey);

    res.json({
      success: true,
      token,
      email: resultUser.email,
    });
  } catch (err) {
    res.json({
      success: false,
      error: err.toString(),
    });
  }
});

///////////////////////////////////////////////////

router.get("/message", (req, res) => {
  try {
    const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
    const token = req.header(tokenHeaderKey);
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const verified = jwt.verify(token, jwtSecretKey);
    if (!verified) {
      return res.json({
        success: false,
        message: "ID Token could not be verified.",
      });
    }

    if (verified.userData && verified.userData.scope === "user") {
      return res.json({
        success: true,
        message: "I am a normal user",
      });
    }

    if (verified.userData && verified.userData.scope === "admin") {
      return res.json({
        success: true,
        message: "I am an admin user",
      });
    }
  } catch (err) {
    res.json({
      success: false,
      error: err.toString(),
    });
  }
});

//////////////////////////////////////////////////

module.exports = router;

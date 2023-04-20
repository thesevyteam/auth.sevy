const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const router = express.Router();
const { v4: uuidv4 } = require("uuid");
const { generateOTP, sendOTPViaEmail, sendOTPViaSMS } = require("../utils/otp");
const { authenticateJWT } = require("../middlewares");

// Registration route
router.post(
  "/register",
  [
    body("email").isEmail(),
    body("password").isLength({ min: 8 }),
    body("phone").isMobilePhone(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {
      email,
      password,
      first_name,
      last_name,
      phone,
      primary_contact,
      role,
      status,
      profile_picture,
      geohash4 = "",
      geohash5 = "",
      geohash6 = "",
    } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const uid = uuidv4();
      await req.db.query(
        "INSERT INTO users (uid, first_name, last_name, email, password, phone, role, status, profile_picture,primary_contact, geohash4, geohash5, geohash6) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          uid,
          first_name,
          last_name,
          email,
          hashedPassword,
          phone,
          role,
          status,
          profile_picture,
          primary_contact,
          geohash4,
          geohash5,
          geohash6,
        ]
      );

      // Generate OTP
      const otp = generateOTP();
      await storeOTP(req, otp, uid);

      // Send OTP
      if (primary_contact === "email") {
        await sendOTPViaEmail(email, otp);
      } else if (primary_contact === "phone") {
        await sendOTPViaSMS(phone, otp);
      }

      res.cookie("token", token, { httpOnly: true, sameSite: "strict" });
      res.status(201).json({
        message:
          "User registered successfully. An OTP has been sent for verification.",
        data: {
          uid,
          first_name,
          last_name,
          email,
          phone,
          role,
          status,
          profile_picture,
          primary_contact,
        },
      });
    } catch (error) {
      console.log(error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Login route
router.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  const [result] = await req.db.query("SELECT * FROM users WHERE email = ?", [
    email,
  ]);

  if (
    result.length === 0 ||
    !(await bcrypt.compare(password, result[0].password))
  ) {
    return res.status(401).json({ error: "Invalid email or password" });
  }

  const token = jwt.sign(
    { uid: result[0].uid, email: result[0].email },
    process.env.JWT_SECRET,
    {
      expiresIn: "1h",
    }
  );

  res.cookie("token", token, { httpOnly: true, sameSite: "strict" });
  res.json({
    data: {
      uid: result[0].uid,
      first_name: result[0].first_name,
      last_name: result[0].last_name,
      email: result[0].email,
      phone: result[0].phone,
      role: result[0].role,
      status: result[0].status,
      profile_picture: result[0].profile_picture,
      primary_contact: result[0].primary_contact,
    },
  });
});

router.post("/verify-otp", async (req, res) => {
  const { uid, otp } = req.body;

  if (!uid || !otp) {
    return res.status(400).json({ error: "UID and OTP are required." });
  }

  const [userRows] = await req.db.query("SELECT * FROM users WHERE uid = ?", [
    uid,
  ]);
  const user = userRows[0];

  if (!user) {
    return res.status(404).json({ error: "User not found." });
  }

  if (user.otp === parseInt(otp) && user.otp_expires_at > new Date()) {
    await req.db.query(
      "UPDATE users SET contact_verified = TRUE, otp = NULL, otp_expires_at = NULL WHERE uid = ?",
      [uid]
    );
    res.status(200).json({ message: "OTP verified successfully." });
  } else {
    res.status(400).json({ error: "Invalid or expired OTP." });
  }
});

router.post("/resend-otp", async (req, res) => {
  try {
    const { email, phone, primary_contact, uid } = req.body;

    // Validate input
    if (!email && !phone) {
      return res
        .status(400)
        .json({ message: "Email or phone number is required" });
    }

    // Generate a new OTP
    const otp = generateOTP();

    // Store the OTP and its expiration time in the database
    await storeOTP(req, otp, uid);

    // Send the OTP via email or SMS
    if (primary_contact === "email") {
      await sendOTPViaEmail(email, otp);
    } else {
      await sendOTPViaSMS(phone, otp);
    }

    res.status(200).json({ message: "OTP resent successfully" });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ message: "An error occurred while resending the OTP" });
  }
});

async function storeOTP(req, otp, uid) {
  await req.db.query(
    "UPDATE users SET otp = ?, otp_expires_at = ? WHERE uid = ?",
    [otp, new Date(Date.now() + 1000 * 60 * 10), uid] // OTP expires in 10 minutes
  );
}

router.post("/refresh", authenticateJWT, (req, res) => {
  const user = req.user;

  // Generate a new access token
  const newAccessToken = jwt.sign(
    { email: user.email, id: user.uid },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "1h",
    }
  );

  // Set the new access token as an HttpOnly cookie
  res.cookie("token", newAccessToken, { httpOnly: true, sameSite: "strict" });
  res.status(200).json({ message: "Token refreshed successfully" });
});

// Protected route example
router.get("/protected", authenticateJWT, async (req, res) => {
  res.json({ message: "You have accessed a protected route!", user: req.user });
});

module.exports = router;

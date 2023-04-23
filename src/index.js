require("dotenv").config();
const helmet = require("helmet");
const morgan = require("morgan");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mysql = require("mysql2/promise");
const authRoutes = require("./v1/routes/auth.route");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(
  cors({
    origin: "*",
    credentials: true,
    optionSuccessStatus: 200,
  })
);

app.use(helmet());
app.use(morgan("common")); // remove before deploying

// Connect to MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Middleware to provide the database connection to routes
app.use(async (req, res, next) => {
  req.db = await pool.getConnection();
  req.db.connection.config.namedPlaceholders = true;
  next();
});

// Routes
app.use("/", authRoutes);

app.listen(process.env.PORT || 5000, (_) => {
  console.log(`App running on 5000`);
});

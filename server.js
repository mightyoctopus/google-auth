const express = require("express");
const bodyParser = require("body-parser");
const pg = require("pg");
const bcrypt = require("bcrypt");
const passport = require("passport");
const { Strategy } = require("passport-local");
const GoogleStrategy = require("passport-google-oauth2");
const session = require("express-session");
const env = require("dotenv");

const app = express();
const port = 8080;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
const basePath = '/auth-app';
app.use(basePath, express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get(`${basePath}/`, (req, res) => {
  res.render("home.ejs", { basePath });
});

app.get(`${basePath}/login`, (req, res) => {
  res.render("login.ejs", { basePath });
});

app.get(`${basePath}/register`, (req, res) => {
  res.render("register.ejs", { basePath });
});

app.get(`${basePath}/logout`, (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect(`${basePath}/`);
  });
});

app.get(`${basePath}/secrets`, async (req, res) => {
  console.log(req.user);

  ////////////////UPDATED GET SECRETS ROUTE/////////////////
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        `SELECT secret FROM users WHERE email = $1`,
        [req.user.email]
      );
      console.log(result);
      const secret = result.rows[0].secret;
      if (secret) {
        res.render("secrets.ejs", { secret: secret, basePath });
      } else {
        res.render("secrets.ejs", { secret: "Jack Bauer is my hero.", basePath });
      }
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect(`${basePath}/login`);
  }
});

////////////////SUBMIT GET ROUTE/////////////////
app.get(`${basePath}/submit`, function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs", { basePath });
  } else {
    res.redirect(`${basePath}/login`);
  }
});

app.get(
  `${basePath}/auth/google`,
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  `${basePath}/auth/google/secrets`,
  passport.authenticate("google", {
    successRedirect: `${basePath}/secrets`,
    failureRedirect: `${basePath}/login`,
  })
);

app.post(
  `${basePath}/login`,
  passport.authenticate("local", {
    successRedirect: `${basePath}/secrets`,
    failureRedirect: `${basePath}/login`,
  })
);

app.post(`${basePath}/register`, async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect(`${basePath}/login`);
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect(`${basePath}/secrets`);
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


////////////////SUBMIT POST ROUTE/////////////////
app.post(`${basePath}/submit`, async function (req, res) {
  const submittedSecret = req.body.secret;
  console.log(req.user);
  try {
    await db.query(`UPDATE users SET secret = $1 WHERE email = $2`, [
      submittedSecret,
      req.user.email,
    ]);
    res.redirect(`${basePath}/secrets`);
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `https://mhhong.dev${basePath}/auth/google/secrets`,
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

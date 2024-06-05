const express = require("express");
const app = express();
const PocketBase = require("pocketbase/cjs");
const pb = new PocketBase("http://127.0.0.1:8090");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const session = require("express-session");
const crypto = require("crypto");

app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");

const secretKey = crypto.randomBytes(64).toString("hex")
// Configure express-session
app.use(
  session({
    secret: secretKey,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 604800000 }, // one week
  })
);

// Configure Passport with Local strategy
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (email, password, done) => {
      // Authenticate user with PocketBase
      pb.collection("users")
        .authWithPassword(email, password)
        .then((authData) => done(null, authData.record))
        .catch((err) => done(err));
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await pb.collection("users").getOne(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

const isLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
};

// Initialize Passport and session
app.use(passport.initialize());
app.use(passport.session());

// set local variables middleware
app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/register", (req, res) => {
  res.render("auth/register");
});

app.post("/register", async (req, res, next) =>{
  try {
    const user = await pb.collection('users').create(req.body);
    req.login({id: user.id}, function(err) {
      if (err) return next(err);
      res.redirect('/profile');
    });
  } catch(err) {
    console.error(err)
    next(err);
  }
});

app.get("/profile", isLoggedIn, (req, res) => {
  res.render("user/profile");
});

// Login route
app.get("/login", (req, res) => {
  res.render("auth/login");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

// Logout route
app.post('/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`);
});

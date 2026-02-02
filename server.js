require("dotenv").config({ path: ".env.local" });

const express = require("express");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const path = require("path");
const { spawn } = require("child_process");

const app = express();
const INACTIVITY_MS = Number(process.env.INACTIVITY_MS) || 6 * 60 * 60 * 1000; // 6 hours


// 1. TRUST PROXY (Essential for Azure/Proxies)
app.set("trust proxy", 1);

// Identify if we are running on Azure or Local
const isProduction = process.env.NODE_ENV === "production" || !!process.env.WEBSITE_HOSTNAME;

/* ======================
   2) Session Setup
   ====================== */
app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "super-secret-key",
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      maxAge: INACTIVITY_MS, // 6 hours
      sameSite: "lax",
      secure: isProduction,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

/* ======================
   3) Passport Strategy
   ====================== */
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
      proxy: true,
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

/* ======================
   4) Auth Middleware
   ===================== */
function ensureAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  console.log("Blocking unauthorized access. Redirecting to /login");
  return res.redirect("/login");
}

// Protect /login paths except the public login assets
app.use("/login", (req, res, next) => {
  const openPaths = new Set(["/login.html", "/login.js", "/styles.css", "/", ""]);
  if (openPaths.has(req.path)) return next();
  res.set("Cache-Control", "no-store");
  return ensureAuth(req, res, next);
});

// ⏱️ Inactivity timeout (1 hour)
const INACTIVITY_LIMIT = 60 * 60 * 1000; // 1 hour

app.use((req, res, next) => {
  if (req.session && req.isAuthenticated?.()) {
    const now = Date.now();

    if (req.session.lastActivity) {
      const idleTime = now - req.session.lastActivity;

      if (idleTime > INACTIVITY_LIMIT) {
        console.log("Session expired due to inactivity");

        return req.logout(err => {
          if (err) return next(err);
          req.session.destroy(() => {
            res.clearCookie("sid");
            return res.redirect("/login");
          });
        });
      }
    }

    // Update activity timestamp
    req.session.lastActivity = now;
  }

  next();
});


/* ======================
   5) Routes
   ====================== */

// ✅ Session check endpoint (used by script.js)
app.get("/api/session", (req, res) => {
  if (!req.user) return res.json({ authenticated: false });

  const profile = req.user || {};
  const displayName =
    profile.displayName ||
    profile.name?.givenName ||
    profile.name ||
    profile.emails?.[0]?.value ||
    "";
  const email = profile.email || profile.emails?.[0]?.value || "";
  const photos = Array.isArray(profile.photos)
    ? profile.photos
    : profile.picture
      ? [{ value: profile.picture }]
      : undefined;

  res.json({
    authenticated: true,
    user: {
      // Preserve the full profile shape used by the client
      ...profile,
      displayName,
      email,
      emails: profile.emails || (email ? [{ value: email }] : undefined),
      photos,
      picture: profile.picture || photos?.[0]?.value || null,
    },
  });
});

// Run whitelisted Python lesson scripts or user-submitted code
app.post("/api/run-python", ensureAuth, express.json(), (req, res) => {
  const { lesson, code } = req.body || {};
  const lessonToScript = {
    print: "python/print_demo.py",
    if: "python/if_demo.py",
    for: "python/for_demo.py",
  };

  const useUserCode = typeof code === "string" && code.trim().length > 0;

  if (useUserCode && code.length > 2000) {
    return res.status(400).json({ error: "Code too long (2000 char limit)" });
  }

  let proc;
  if (useUserCode) {
    // Run inline user code safely with -c (still not sandboxed; meant for demo)
    proc = spawn("python3", ["-c", code], {
      cwd: __dirname,
    });
  } else {
    const script = lessonToScript[lesson];
    if (!script) {
      return res.status(400).json({ error: "Unknown lesson" });
    }
    proc = spawn("python3", [path.join(__dirname, script)], {
      cwd: __dirname,
    });
  }

  let stdout = "";
  let stderr = "";

  proc.stdout.on("data", (data) => (stdout += data.toString()));
  proc.stderr.on("data", (data) => (stderr += data.toString()));

  proc.on("close", (code) => {
    if (code !== 0) {
      return res
        .status(500)
        .json({ error: stderr.trim() || "Python process failed" });
    }
    res.json({ output: stdout.trim() });
  });
});

// Default Home (PUBLIC)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Public login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login", "login.html"));
});

// Public signup page
app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "login", "signup.html"));
});

// Start Google OAuth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Google Callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    console.log("Login Successful for:", req.user.displayName);
    // Redirect to protected dashboard route
    res.redirect("/login/dashboard.html");
  }
);

// Protected Dashboard Route
app.get("/login/dashboard.html", ensureAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "login", "dashboard.html"));
});

// Legacy python course path -> redirect to data-driven page
app.get("/login/python-course.html", ensureAuth, (req, res) => {
  res.redirect("/login/course-topic.html?course=python");
});

// Logout
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie("sid");
      res.redirect("/login");
    });
  });
});

/* ======================
   6) Static Files & Server
   ====================== */
// Serve static files AFTER defining protected routes
app.use(express.static(__dirname));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${isProduction ? "Production/Azure" : "Development"}`);
});

  require("dotenv").config();
  const express = require("express");
  const cors = require("cors");
  const cookieParser = require("cookie-parser");
  const passport = require("passport");
  const GoogleStrategy = require("passport-google-oauth20").Strategy;
  const jwt = require("jsonwebtoken");
  const { google } = require("googleapis");

  const app = express();
  const PORT = process.env.PORT || 5000;

  app.use(
    cors({
      origin: ["http://localhost:5173", "https://texteditormain.netlify.app"], // ✅ Array format
      credentials: true,
    })
  );

  app.use(express.json());
  app.use(cookieParser());

  // Passport Google Strategy
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
      },
      (accessToken, refreshToken, profile, done) => {
        profile.accessToken = accessToken;
        return done(null, profile);
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user);
  });
  passport.deserializeUser((obj, done) => {
    done(null, obj);
  });

  // Google Auth Route
  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
  );

  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
      const token = jwt.sign({ user: req.user, accessToken: req.user.accessToken }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      res.cookie("token", token, { httpOnly: true });
      res.redirect("https://texteditormain.netlify.app");
    }
  );

  const authenticate = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    jwt.verify(token, process.env.JWT_SECRET, (err, data) => {
      if (err) return res.status(403).json({ message: "Invalid Token" });
      req.user = data.user;
      req.accessToken = data.accessToken;
      next();
    });
  };

  app.get("/fetch-letters", async (req, res) => {
    console.log("📡 Fetch request received");

    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        console.log("❌ Unauthorized request - No token");
        return res.status(401).json({ message: "Unauthorized: No token provided" });
      }

      const accessToken = authHeader.split(" ")[1];
      console.log("🔑 Using Access Token:", accessToken);

      const auth = new google.auth.OAuth2();
      auth.setCredentials({ access_token: accessToken });

      const drive = google.drive({ version: "v3", auth });

      // Get "Letter" folder ID
      const folderResponse = await drive.files.list({
        q: "name='Letter' and mimeType='application/vnd.google-apps.folder' and 'root' in parents",
        fields: "files(id)",
      });

      if (folderResponse.data.files.length === 0) {
        console.log("❌ No 'Letter' folder found");
        return res.json([]);
      }

      const folderId = folderResponse.data.files[0].id;

      // Fetch only files inside "Letter" folder
      const response = await drive.files.list({
        q: `'${folderId}' in parents and mimeType='application/vnd.google-apps.document'`,
        fields: "files(id, name, mimeType)",
      });

      console.log("✅ Files Fetched from 'Letter' folder:", response.data.files);
      res.json(response.data.files);
    } catch (error) {
      console.error("❌ Error Fetching Letters:", error);
      res.status(500).json({ message: "Error fetching letters", error });
    }
  });




  app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/");
  });

  app.get("/user", (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    jwt.verify(token, process.env.JWT_SECRET, (err, data) => {
      if (err) return res.status(403).json({ message: "Invalid Token" });
      res.json(data.user);
    });
  });


  app.post("/save-letter", (req, res) => {
      const { content } = req.body;
    
      if (!content) {
        return res.status(400).json({ message: "Content cannot be empty" });
      }
    
      console.log("Letter content:", content);
      res.status(200).json({ message: "Letter saved successfully" });
    });
    

  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

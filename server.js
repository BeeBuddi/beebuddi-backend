Got it — I can see everything. Here is your complete new `server.js` with:

- ✅ Your copyright header preserved
- ✅ Everything that's already working kept exactly as-is
- ✅ JWT register and login routes added
- ✅ Auth middleware added
- ✅ Protected routes updated
- ✅ `bcryptjs` and `jsonwebtoken` added

---

**Copy this entire file and replace your current `server.js` in GitHub:**

```javascript
// Copyright (c) 2026 Kevin Paul Norton
// All rights reserved. Unauthorized use prohibited.

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const Stripe = require("stripe");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 4000;

// ENV (set these in Render)
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "sk_test_xxx";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "whsec_xxx";
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || "changeme_in_render";

const stripe = new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: "2023-10-16",
});

// Connect to MongoDB
if (MONGODB_URI) {
  mongoose
    .connect(MONGODB_URI)
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error("MongoDB connection error:", err));
} else {
  console.warn("No MONGODB_URI set — running without database");
}

// --- Mongoose Schemas ---

const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  email: { type: String, default: null },
  passwordHash: { type: String, default: null },
  stripeCustomerId: { type: String, default: null },
  subscriptionStatus: {
    type: String,
    default: "expired",
    enum: ["active", "master", "expired", "past_due", "canceled"],
  },
  masterKeyUsed: { type: String, default: null },
});

const masterKeySchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  maxUses: { type: Number, default: 50 },
  usedBy: { type: [String], default: [] },
});

const User = mongoose.model("User", userSchema);
const MasterKey = mongoose.model("MasterKey", masterKeySchema);

// Seed master keys if they don't exist
async function seedMasterKeys() {
  const keys = [
    { code: "BEEBUDDI-VIP-KEVIN", maxUses: 5 },
    { code: "BEEBUDDI-LIFETIME-ALPHA", maxUses: 50 },
  ];
  for (const k of keys) {
    await MasterKey.findOneAndUpdate({ code: k.code }, k, { upsert: true });
  }
}
mongoose.connection.once("open", seedMasterKeys);

// --- Middleware ---

app.use(cors());
app.use(bodyParser.json());

// JWT Auth Middleware — verifies token on protected routes
function requireAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid token" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token expired or invalid" });
  }
}

// Attach user from DB (used on subscription + master key routes)
async function attachUser(req, res, next) {
  const userId = req.userId || req.headers["x-user-id"] || req.query.userId || null;
  if (!userId) {
    req.user = null;
    return next();
  }
  let user = await User.findOne({ userId });
  if (!user) {
    user = await User.create({ userId });
  }
  req.user = user;
  next();
}

// Enforce active or master subscription
function enforceSubscription(req, res, next) {
  const user = req.user;
  if (!user) return res.status(401).json({ error: "Unauthenticated" });
  if (
    user.subscriptionStatus === "active" ||
    user.subscriptionStatus === "master"
  ) {
    return next();
  }
  return res.status(403).json({
    error: "Subscription inactive",
    status: user.subscriptionStatus,
  });
}

// --- Stripe Webhook ---

app.post(
  "/webhook/stripe",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    let event;
    try {
      const sig = req.headers["stripe-signature"];
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    const data = event.data.object;

    switch (event.type) {
      case "customer.subscription.created":
      case "customer.subscription.updated":
        await updateUserByCustomer(data.customer, data.status);
        break;
      case "customer.subscription.deleted":
        await updateUserByCustomer(data.customer, "canceled");
        break;
      case "invoice.payment_failed":
        await updateUserByCustomer(data.customer, "past_due");
        break;
    }

    res.json({ received: true });
  }
);

async function updateUserByCustomer(customerId, status) {
  let mapped = "canceled";
  if (status === "active" || status === "trialing") mapped = "active";
  else if (status === "past_due" || status === "unpaid") mapped = "past_due";

  const result = await User.updateMany(
    { stripeCustomerId: customerId, subscriptionStatus: { $ne: "master" } },
    { subscriptionStatus: mapped }
  );
  console.log(`Updated ${result.modifiedCount} user(s) to ${mapped}`);
}

// --- Auth Routes ---

// Register a new user
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const existing = await User.findOne({ email });
  if (existing)
    return res.status(400).json({ error: "Email already registered" });

  const passwordHash = await bcrypt.hash(password, 10);
  const userId = new mongoose.Types.ObjectId().toString();

  const user = await User.create({ userId, email, passwordHash });

  const token = jwt.sign({ userId: user.userId }, JWT_SECRET, {
    expiresIn: "30d",
  });

  res.json({ ok: true, token, userId: user.userId });
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  const user = await User.findOne({ email });
  if (!user || !user.passwordHash)
    return res.status(401).json({ error: "Invalid email or password" });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match)
    return res.status(401).json({ error: "Invalid email or password" });

  const token = jwt.sign({ userId: user.userId }, JWT_SECRET, {
    expiresIn: "30d",
  });

  res.json({ ok: true, token, userId: user.userId });
});

// --- Routes ---

app.get("/api/subscription-status", requireAuth, attachUser, (req, res) => {
  const user = req.user;
  if (!user) return res.status(401).json({ error: "Missing user" });
  res.json({ status: user.subscriptionStatus });
});

app.post("/api/activate-master-key", requireAuth, attachUser, async (req, res) => {
  const user = req.user;
  if (!user) return res.status(401).json({ error: "Missing user" });

  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Missing code" });

  const key = await MasterKey.findOne({ code });
  if (!key) return res.status(400).json({ error: "Invalid code" });

  if (key.maxUses && key.usedBy.length >= key.maxUses) {
    return res.status(400).json({ error: "Code has reached its limit" });
  }

  if (!key.usedBy.includes(user.userId)) {
    key.usedBy.push(user.userId);
    await key.save();
  }

  user.subscriptionStatus = "master";
  user.masterKeyUsed = code;
  await user.save();

  res.json({ ok: true, status: "master" });
});

app.post(
  "/api/inspections/create",
  requireAuth,
  attachUser,
  enforceSubscription,
  (req, res) => {
    res.json({ ok: true, message: "Inspection created (demo)" });
  }
);

app.post(
  "/api/inspections/export",
  requireAuth,
  attachUser,
  enforceSubscription,
  (req, res) => {
    res.json({ ok: true, message: "Export generated (demo)" });
  }
);

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(port, () => {
  console.log(`BeeBuddi backend running on http://localhost:${port}`);
});
```

---


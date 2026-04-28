// Copyright (c) 2026 Kevin Paul Norton
// All rights reserved. Unauthorized use prohibited.

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const Stripe = require("stripe");

const app = express();
const port = process.env.PORT || 4000;

// ENV (set these in Render/Railway)
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "sk_test_xxx";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "whsec_xxx";

const stripe = new Stripe(STRIPE_SECRET_KEY, {
  apiVersion: "2023-10-16",
});

// JSON routes
app.use(cors());
app.use(bodyParser.json());

// In-memory store (replace with DB later)
const users = new Map();
const masterKeys = new Map();

// Example master keys
masterKeys.set("BEEBUDDI-VIP-KEVIN", { maxUses: 5, usedBy: new Set() });
masterKeys.set("BEEBUDDI-LIFETIME-ALPHA", { maxUses: 50, usedBy: new Set() });

// Auth stub
function getUserIdFromRequest(req) {
  return req.headers["x-user-id"] || req.query.userId || null;
}

function attachUser(req, res, next) {
  const userId = getUserIdFromRequest(req);
  if (!userId) {
    req.user = null;
    return next();
  }
  const user =
    users.get(userId) || {
      stripeCustomerId: null,
      subscriptionStatus: "expired",
      masterKeyUsed: null,
    };
  users.set(userId, user);
  req.user = { id: userId, ...user };
  next();
}

app.use(attachUser);

// Subscription enforcement
function enforceSubscription(req, res, next) {
  const user = req.user;
  if (!user) return res.status(401).json({ error: "Unauthenticated" });

  if (user.subscriptionStatus === "active" || user.subscriptionStatus === "master") {
    return next();
  }

  return res.status(403).json({
    error: "Subscription inactive",
    status: user.subscriptionStatus,
  });
}

// Stripe webhook
app.post(
  "/webhook/stripe",
  bodyParser.raw({ type: "application/json" }),
  (req, res) => {
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
      case "customer.subscription.updated": {
        const customerId = data.customer;
        const status = data.status;
        updateUserSubscriptionByCustomer(customerId, status);
        break;
      }
      case "customer.subscription.deleted": {
        updateUserSubscriptionByCustomer(data.customer, "canceled");
        break;
      }
      case "invoice.payment_failed": {
        updateUserSubscriptionByCustomer(data.customer, "past_due");
        break;
      }
    }

    res.json({ received: true });
  }
);

function updateUserSubscriptionByCustomer(customerId, status) {
  for (const [userId, user] of users.entries()) {
    if (user.stripeCustomerId === customerId && user.subscriptionStatus !== "master") {
      let mapped = "canceled";
      if (status === "active" || status === "trialing") mapped = "active";
      else if (status === "past_due" || status === "unpaid") mapped = "past_due";

      user.subscriptionStatus = mapped;
      users.set(userId, user);
      console.log(`Updated user ${userId} subscription to ${mapped}`);
    }
  }
}

// Get subscription status
app.get("/api/subscription-status", (req, res) => {
  const user = req.user;
  if (!user) return res.status(401).json({ error: "Missing user" });

  res.json({ status: user.subscriptionStatus });
});

// Activate master key
app.post("/api/activate-master-key", (req, res) => {
  const user = req.user;
  if (!user) return res.status(401).json({ error: "Missing user" });

  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Missing code" });

  const key = masterKeys.get(code);
  if (!key) return res.status(400).json({ error: "Invalid code" });

  if (key.maxUses && key.usedBy.size >= key.maxUses) {
    return res.status(400).json({ error: "Code has reached its limit" });
  }

  key.usedBy.add(user.id);
  masterKeys.set(code, key);

  const updatedUser = {
    ...user,
    subscriptionStatus: "master",
    masterKeyUsed: code,
  };
  users.set(user.id, updatedUser);

  res.json({ ok: true, status: "master" });
});

// Protected routes
app.post("/api/inspections/create", enforceSubscription, (req, res) => {
  res.json({ ok: true, message: "Inspection created (demo)" });
});

app.post("/api/inspections/export", enforceSubscription, (req, res) => {
  res.json({ ok: true, message: "Export generated (demo)" });
});
// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(port, () => {
  console.log(`BeeBuddi backend running on http://localhost:${port}`);
});

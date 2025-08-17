require('dotenv').config(); // Load environment variables first
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const knex = require("knex");
const path = require("path");

// === SQLite DB config ===
const db = knex({
  client: "sqlite3",
  connection: { filename: "./taskflow.db" },
  useNullAsDefault: true,
});

const JWT_SECRET = process.env.JWT_SECRET || "your-strong-secret-key";
const JWT_EXPIRE = "24h";

// Auto-migrate tables on start
(async function migrate() {
  try {
    // Create users table if not exists
    if (!(await db.schema.hasTable("users"))) {
      await db.schema.createTable("users", (t) => {
        t.increments("id").primary();
        t.string("username").unique().notNullable();
        t.string("email").unique().notNullable();
        t.string("password").notNullable();
        t.boolean("browser_notifications").defaultTo(true);
      });
      console.log("Created users table");
    }
    
    // Create tasks table if not exists
    if (!(await db.schema.hasTable("tasks"))) {
      await db.schema.createTable("tasks", (t) => {
        t.increments("id").primary();
        t.string("title").notNullable();
        t.text("description");
        t.string("priority").notNullable();
        t.string("status").notNullable();
        t.string("dueDate");
        t.boolean("completed").defaultTo(false);
        t.integer("user_id").references("id").inTable("users");
        t.datetime("created_at").defaultTo(db.fn.now());
      });
      console.log("Created tasks table");
    }

    // Update email_notifications column to browser_notifications if exists
    if (await db.schema.hasColumn("users", "email_notifications")) {
      await db.schema.alterTable("users", (t) => {
        t.renameColumn("email_notifications", "browser_notifications");
      });
      console.log("Renamed email_notifications to browser_notifications");
    }

    // Add browser_notifications column if missing
    if (!(await db.schema.hasColumn("users", "browser_notifications"))) {
      await db.schema.alterTable("users", (t) => {
        t.boolean("browser_notifications").defaultTo(true);
      });
      console.log("Added browser_notifications to users");
    }

    // Remove reminder_sent column if exists (no longer needed)
    if (await db.schema.hasColumn("tasks", "reminder_sent")) {
      await db.schema.alterTable("tasks", (t) => {
        t.dropColumn("reminder_sent");
      });
      console.log("Removed reminder_sent column from tasks");
    }

    // Add created_at column if missing (SQLite compatible)
    if (!(await db.schema.hasColumn("tasks", "created_at"))) {
      await db.schema.alterTable("tasks", (t) => {
        t.datetime("created_at");
      });
      
      // Set default value for existing rows
      await db("tasks").update({ created_at: new Date().toISOString() });
      console.log("Added created_at to tasks");
    }

    console.log("Database tables ready with browser notification support");
  } catch (error) {
    console.error("Migration error:", error);
  }
})();

const app = express();

// Enable CORS for all routes
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Handle favicon.ico
app.get('/favicon.ico', (req, res) => res.status(204).send());

// === Auth helpers ===
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: JWT_EXPIRE,
  });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }
  try {
    const decoded = jwt.verify(auth.split(" ")[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// === Auth routes ===

// Register
app.post(
  "/api/auth/register",
  [
    body("username").trim().isLength({ min: 3 }).withMessage("Username must be at least 3 characters"),
    body("email").isEmail().withMessage("Invalid email"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Invalid input", errors: errors.array() });
    }

    const { username, email, password } = req.body;
    try {
      const existing = await db("users").where({ email }).orWhere({ username }).first();
      if (existing) {
        return res.status(400).json({ message: "Email or Username already exists" });
      }
      
      const hashed = await bcrypt.hash(password, 10);
      await db("users").insert({ 
        username, 
        email, 
        password: hashed,
        browser_notifications: true 
      });
      return res.status(201).json({ message: "Registration successful" });
    } catch (err) {
      console.error("Registration error:", err);
      return res.status(500).json({ message: "Registration failed" });
    }
  }
);

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await db("users").where({ email }).first();
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Incorrect email or password" });
    }
    
    const token = signToken(user);
    return res.json({
      access_token: token,
      token_type: "bearer",
      username: user.username,
      email: user.email 
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Login failed" });
  }
});

// Forgot password
app.post("/api/auth/forgot-password", async (req, res) => {
  return res.json({ message: "If the email is registered, password reset instructions will be sent." });
});

// === Task routes ===

// Get all tasks
app.get("/api/tasks", requireAuth, async (req, res) => {
  try {
    const tasks = await db("tasks").where({ user_id: req.user.id }).orderBy("id", "asc");
    return res.json(tasks);
  } catch (err) {
    console.error("Get tasks error:", err);
    return res.status(500).json({ message: "Failed to fetch tasks" });
  }
});

// Get tasks due soon (for notifications)
app.get("/api/tasks/due-soon", requireAuth, async (req, res) => {
  try {
    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    const todayString = today.toISOString().split('T')[0];
    const tomorrowString = tomorrow.toISOString().split('T')[0];

    const dueTasks = await db("tasks")
      .where({ user_id: req.user.id })
      .where("completed", false)
      .whereIn("dueDate", [todayString, tomorrowString])
      .orderBy("dueDate", "asc");

    const tasksWithDays = dueTasks.map(task => {
      const dueDate = new Date(task.dueDate);
      const daysUntilDue = Math.ceil((dueDate - today) / (1000 * 60 * 60 * 24));
      return {
        ...task,
        daysUntilDue: daysUntilDue
      };
    });

    return res.json(tasksWithDays);
  } catch (err) {
    console.error("Get due tasks error:", err);
    return res.status(500).json({ message: "Failed to fetch due tasks" });
  }
});

// Create a new task
app.post("/api/tasks", requireAuth, async (req, res) => {
  const { title, description = "", priority = "medium", status = "pending", dueDate } = req.body;
  if (!title) {
    return res.status(400).json({ message: "Task title is required" });
  }
  
  try {
    const completed = status === "completed";
    const [id] = await db("tasks").insert({
      title,
      description,
      priority,
      status,
      dueDate,
      completed,
      user_id: req.user.id,
      created_at: new Date().toISOString()
    });
    const task = await db("tasks").where({ id }).first();
    return res.status(201).json(task);
  } catch (err) {
    console.error("Create task error:", err);
    return res.status(500).json({ message: "Failed to create task" });
  }
});

// Update a task
app.put("/api/tasks/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const updates = req.body;
  try {
    const task = await db("tasks").where({ id, user_id: req.user.id }).first();
    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    if (updates.status === "completed") updates.completed = true;
    else if (updates.status) updates.completed = false;

    await db("tasks").where({ id }).update(updates);
    const updated = await db("tasks").where({ id }).first();
    return res.json(updated);
  } catch (err) {
    console.error("Update task error:", err);
    return res.status(500).json({ message: "Failed to update task" });
  }
});

// Delete a task
app.delete("/api/tasks/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const count = await db("tasks").where({ id, user_id: req.user.id }).del();
    if (!count) {
      return res.status(404).json({ message: "Task not found" });
    }
    return res.json({ message: "Task deleted" });
  } catch (err) {
    console.error("Delete task error:", err);
    return res.status(500).json({ message: "Failed to delete task" });
  }
});

// === User Settings Routes ===

// Get user profile
app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const user = await db("users").where({ id: req.user.id }).first();
    return res.json({ 
      username: user.username, 
      email: user.email, 
      browser_notifications: user.browser_notifications 
    });
  } catch (err) {
    console.error("Get profile error:", err);
    return res.status(500).json({ message: "Failed to get user profile" });
  }
});

// Update user settings
app.put("/api/me", requireAuth, async (req, res) => {
  try {
    const { browser_notifications } = req.body;
    await db("users").where({ id: req.user.id }).update({ browser_notifications });
    
    const user = await db("users").where({ id: req.user.id }).first();
    return res.json({ 
      username: user.username, 
      email: user.email, 
      browser_notifications: user.browser_notifications 
    });
  } catch (err) {
    console.error("Update settings error:", err);
    return res.status(500).json({ message: "Failed to update settings" });
  }
});

// Delete user account and all data
app.delete("/api/me/delete-account", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Start a transaction to ensure data consistency
    await db.transaction(async trx => {
      // Delete all user's tasks
      await trx("tasks").where("user_id", userId).del();
      
      // Delete the user account
      const deletedCount = await trx("users").where("id", userId).del();
      
      if (deletedCount === 0) {
        throw new Error("User not found");
      }
    });
    
    return res.json({ message: "Account and all data deleted successfully" });
  } catch (err) {
    console.error("Delete account error:", err);
    return res.status(500).json({ message: "Failed to delete account" });
  }
});

// Root endpoint
app.get("/", (req, res) => {
  return res.json({ 
    message: "TaskFlow backend running", 
    features: ["Authentication", "Task Management", "Browser Notifications"] 
  });
});

// Health check
app.get("/api/health", (req, res) => {
  return res.json({ 
    status: "OK", 
    timestamp: new Date().toISOString(),
    features: {
      database: "Connected",
      notifications: "Browser-based",
      reminders: "Client-side"
    }
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error("Express error:", err);
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(400).json({ message: "Invalid JSON payload" });
  }
  res.status(500).json({ message: "Internal Server Error" });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`🔔 Browser notifications enabled`);
  console.log(`📋 Task management with client-side reminders`);
});
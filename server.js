const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const cron = require("node-cron");
const fs = require("fs");
const crypto = require("crypto");
const xlsx = require("xlsx"); // Import the xlsx library
require("dotenv").config();

const app = express();
const port = process.env.PORT;
if (!port) {
  console.error("Error : PORT is not defined");
  process.exit(1);
}

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync("./ca (1).pem"),
  },
  connectTimeout: 10000,
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to database:", err);
    return;
  }
  console.log("Connected to database");
});

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: "https://sungadentalclinic.com",
    credentials: true,
  })
);

const addSessionAction = (opts, cb) => {
  const { sessionId, userId, ip, ua, meta, status, action, logoutAt } = opts;
  if (!sessionId) return cb && cb(new Error("no sessionId"));

  db.query(
    "SELECT login_at FROM user_sessions WHERE session_id = ? AND login_at IS NOT NULL ORDER BY id DESC LIMIT 1",
    [sessionId],
    (selErr, loginRows) => {
      if (selErr)
        console.error("Failed to fetch login_at for session:", selErr);
      const loginAt = loginRows && loginRows[0] ? loginRows[0].login_at : null;

      db.query(
        "SELECT meta FROM user_sessions WHERE session_id = ? ORDER BY id DESC LIMIT 1",
        [sessionId],
        (metaErr, metaRows) => {
          if (metaErr)
            console.error("Failed to fetch meta for session:", metaErr);

          let storedMeta = null;
          try {
            if (metaRows && metaRows[0] && metaRows[0].meta) {
              const raw = metaRows[0].meta;
              storedMeta =
                typeof raw === "string"
                  ? JSON.parse(raw)
                  : Buffer.isBuffer(raw)
                  ? JSON.parse(raw.toString("utf8"))
                  : raw;
            }
          } catch (parseErr) {
            console.error("Failed to parse stored meta:", parseErr);
            storedMeta = null;
          }

          const finalMeta = Object.assign({}, storedMeta || {}, meta || {});

          const insertSql = `
            INSERT INTO user_sessions
              (session_id, user_id, ip, user_agent, meta, status, login_at, logout_at, last_seen, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)
          `;
          const params = [
            sessionId,
            userId || null,
            ip || "",
            ua || "",
            JSON.stringify(finalMeta || {}),
            status || "active",
            loginAt,
            logoutAt || null,
            action || null,
          ];

          db.query(insertSql, params, (insErr, res) => {
            if (insErr)
              console.error("Failed to insert session action row:", insErr);
            if (cb) cb(insErr, res);
          });
        }
      );
    }
  );
};

const cookieAuthMiddleware = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "No token provided." });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    req.sessionId = decoded.sessionId || null;

    if (req.sessionId) {
      db.query(
        "UPDATE user_sessions SET last_seen = NOW() WHERE session_id = ?",
        [req.sessionId],
        (err) => {
          if (err) console.error("update last_seen error:", err);
        }
      );
    }

    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
};

cron.schedule("0 0 * * *", async () => {
  console.log("Running scheduler to check unconfirmed appointments...");

  const sql = `
    SELECT firstName, lastName, contact, dentalProcedure, date
    FROM appointments
    WHERE status = 'not confirmed'
  `;

  db.query(sql, async (err, results) => {
    if (err) {
      console.error("Error fetching unconfirmed appointments:", err);
      return;
    }

    const now = new Date().setHours(0, 0, 0, 0);
    results.forEach(async (appointment) => {
      const appointmentDate = new Date(appointment.date).setHours(0, 0, 0, 0);

      if (appointmentDate < now) {
        const { firstName, lastName, contact, dentalProcedure } = appointment;

        try {
          const message = `Hi ${firstName} ${lastName}, your dental appointment for ${dentalProcedure} has passed. Please set another appointment. Thank you!`;

          const smsRes = await axios.post(
            "https://api.semaphore.co/api/v4/messages",
            {
              apikey: process.env.SEMAPHORE_API_KEY,
              number: contact,
              message: message,
              sendername: "SUNGACLINIC",
            }
          );

          console.log(`Message sent to ${contact}:`, smsRes.data);
        } catch (smsErr) {
          console.error(
            `Error sending SMS to ${contact}:`,
            smsErr.response?.data || smsErr.message
          );
        }
      }
    });
  });
});

//make a api for signup here
app.post("/api/users", async (req, res) => {
  const { name, userName, password, role } = req.body;
  if (!name || !userName || !password || !role) {
    return res.status(400).json({ message: "All fields are required." });
  }

  const checksql = "SELECT * FROM users WHERE userName = ?";
  db.query(checksql, [userName], async (err, results) => {
    if (err) {
      console.error("Error checking username:", err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length > 0) {
      return res.status(400).json({ message: "Username already taken." });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const sql =
        "INSERT INTO users(name,userName, password, role) VALUES (?, ?, ?,?)";
      db.query(sql, [name, userName, hashedPassword, role], (err, result) => {
        if (err) {
          console.error("Error inserting user:", err);
          return res.status(500).json({ message: "Error inserting user." });
        }
        res.status(201).json({ message: "User created successfully" });
      });
    } catch (err) {
      console.error("Error hashing password:", err);
      res.status(500).json({ message: "Error processing request." });
    }
  });
});

const getPHDateTime = () => {
  const now = new Date();
  const phTime = now.toLocaleString("en-PH", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "Asia/Manila",
  });

  const [datePart, timePart] = phTime.split(", ");
  const [month, day, year] = datePart.split("/");
  return `${year}-${month}-${day} ${timePart}`;
};

app.post("/api/login", (req, res) => {
  console.log("Login request body:", req.body);
  const { userName, password } = req.body;

  if (!userName || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required." });
  }
  const sql = "SELECT * FROM users WHERE  userName = ?";
  db.query(sql, [userName], async (err, results) => {
    if (err) {
      console.error("Error fetching user:", err);
      return res.status(500).json({ message: "Databse error." });
    }
    if (results.length === 0) {
      res.status(401).json({ message: "Invalid credentials." });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    const sessionId = crypto.randomUUID();
    const token = jwt.sign(
      {
        id: user.id,
        userName: user.userName,
        role: user.role,
        sessionId,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // set cookie
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "none",
      secure: true,
      maxAge: 60 * 60 * 1000,
    });

    // build meta
    const meta = {
      name: user.name || null,
      userName: user.userName || null,
      role: user.role || null,
      lastName: user.lastName || null,
      address: user.address || null,
      contact: user.contact || null,
    };

    const ip = req.ip || req.headers["x-forwarded-for"] || "";
    const ua = req.get("User-Agent") || "";

    // Get current PH time
    const mysqlDatetime = getPHDateTime();

    const insertSql = `
      INSERT INTO user_sessions (session_id, user_id, ip, user_agent, meta, status, login_at, action)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(
      insertSql,
      [
        sessionId,
        user.id,
        ip,
        ua,
        JSON.stringify(meta),
        "active",
        mysqlDatetime,
        "login",
      ],
      (sessErr) => {
        if (sessErr) console.error("Failed to create user session:", sessErr);
        return res.json({
          message: "Login successful",
          user: { id: user.id, userName: user.userName, role: user.role },
        });
      }
    );
  });
});

app.get("/api/users/admin-exists", (req, res) => {
  const sql = "SELECT COUNT(*) AS count FROM users WHERE role = 'admin'";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error checking admin:", err);
      return res.status(500).json({ message: "Database error." });
    }
    const adminExists = results[0].count > 0;
    res.json({ adminExists });
  });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const sessionId = decoded.sessionId;
      const userId = decoded.id;
      if (sessionId) {
        // Get current PH time
        const mysqlDatetime = getPHDateTime();
        const ip = req.ip || req.headers["x-forwarded-for"] || "";
        const ua = req.get("User-Agent") || "";
        const meta = {
          userName: decoded.userName || null,
          role: decoded.role || null,
        };

        const insertSql = `
          INSERT INTO user_sessions
            (session_id, user_id, ip, user_agent, meta, status, login_at, logout_at, last_seen, action)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)
        `;

        // replaced by helper to preserve login_at
        addSessionAction(
          {
            sessionId,
            userId,
            ip,
            ua,
            meta,
            status: "inactive",
            action: "logout",
            logoutAt: mysqlDatetime,
          },
          (err) => {
            if (err) console.error("Error inserting logout session row:", err);
            res.clearCookie("token", {
              httpOnly: true,
              sameSite: "none",
              secure: true,
            });
            return res.json({ message: "Logged out successfully" });
          }
        );
        return;
      }
    } catch (err) {
      console.error("logout decode error:", err);
    }
  }
  res.clearCookie("token", { httpOnly: true, sameSite: "none", secure: true });
  res.json({ message: "Logged out successfully" });
});

app.get("/api/protected", cookieAuthMiddleware, (req, res) => {
  res.json({ message: "You are authenticated!", user: req.user });
});

app.post("/api/user-info", cookieAuthMiddleware, (req, res) => {
  const { lastName, address, contact } = req.body;
  const { userName } = req.user;

  if (!lastName || !address || !contact) {
    return res.status(400).json({ message: "All fields are required." });
  }

  const sql = `
    UPDATE users
    SET lastName = ?,  address = ?, contact = ?
    WHERE userName = ?
  `;
  db.query(sql, [lastName, address, contact, userName], (err, result) => {
    if (err) {
      console.error("Error updating user info:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json({ message: "User info updated successfully." });
  });
});

app.post("/api/appointments", cookieAuthMiddleware, (req, res) => {
  const {
    userName,
    firstName,
    lastName,
    address,
    contact,
    date,
    time,
    status,
    dentalProcedure,
  } = req.body;

  if (
    !userName ||
    !firstName ||
    !lastName ||
    !address ||
    !contact ||
    !date ||
    !time ||
    !status ||
    !dentalProcedure
  ) {
    return res.status(400).json({ message: "All fields are required." });
  }

  const checkSql = `
    SELECT * FROM appointments WHERE userName = ? AND date = ?
  `;
  db.query(checkSql, [userName, date], (err, results) => {
    if (err) {
      console.error("Error checking existing appointment:", err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length > 0) {
      return res.status(400).json({
        message: "You already have an appointment on this date.",
      });
    }

    const checkProcedureSql = `
      SELECT * FROM appointments WHERE dentalProcedure = ? AND date = ?
    `;
    db.query(checkProcedureSql, [dentalProcedure, date], (err2, results2) => {
      if (err2) {
        console.error("Error checking dental procedure:", err2);
        return res.status(500).json({ message: "Database error." });
      }
      if (results2.length > 0) {
        return res.status(400).json({
          message: "This dental procedure is already booked on this date.",
        });
      }

      const sql = `
        INSERT INTO appointments
        (userName, firstName, lastName, address, contact, date, time, status, dentalProcedure)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      db.query(
        sql,
        [
          userName,
          firstName,
          lastName,
          address,
          contact,
          date,
          time,
          status,
          dentalProcedure,
        ],
        (err, result) => {
          if (err) {
            console.error("Error saving appointment:", err);
            return res.status(500).json({ message: "Database error." });
          }

          // record action as new session row (non-blocking)
          if (req.sessionId && req.user) {
            const ip = req.ip || req.headers["x-forwarded-for"] || "";
            const ua = req.get("User-Agent") || "";
            const meta = {
              userName: req.user.userName || null,
              role: req.user.role || null,
            };

            const insertSql = `
              INSERT INTO user_sessions
                (session_id, user_id, ip, user_agent, meta, status, login_at, logout_at, last_seen, action)
              VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NOW(), ?)
            `;
            addSessionAction(
              {
                sessionId: req.sessionId,
                userId: req.user.id,
                ip,
                ua,
                meta,
                status: "active",
                action: "set_appointment",
              },
              (uErr) => {
                if (uErr)
                  console.error("Failed to create session action row:", uErr);
              }
            );
          }

          res.status(201).json({ message: "Appointment saved successfully." });
        }
      );
    });
  });
});

app.post(
  "/api/appointments/:id/confirm",
  cookieAuthMiddleware,
  async (req, res) => {
    const { id } = req.params;
    const { contact, firstName, lastName, dentalProcedure, date } = req.body;

    const sql = "UPDATE appointments SET status = 'confirmed' WHERE id = ?";
    db.query(sql, [id], async (err, result) => {
      if (err) {
        console.error("Error updating appointment status:", err);
        return res.status(500).json({ message: "Database error." });
      }

      let formattedDate = "";
      try {
        formattedDate = new Date(date).toLocaleDateString("en-PH", {
          year: "numeric",
          month: "long",
          day: "numeric",
          timeZone: "Asia/Manila",
        });
      } catch {
        formattedDate = date;
      }

      try {
        const smsRes = await axios.post(
          "https://api.semaphore.co/api/v4/messages",
          {
            apikey: process.env.SEMAPHORE_API_KEY,
            number: contact,
            message: `Hi ${firstName} ${lastName}, your dental appointment for ${dentalProcedure} on ${formattedDate} is confirmed. Thank you!`,
            sendername: "SUNGACLINIC",
          }
        );
        res.json({
          message: "Appointment confirmed and SMS sent.",
          sms: smsRes.data,
        });
      } catch (smsErr) {
        console.error(
          "Error sending SMS:",
          smsErr.response?.data || smsErr.message
        );
        res
          .status(200)
          .json({ message: "Appointment confirmed, but failed to send SMS." });
      }
    });
  }
);
app.post("/api/appointments/:id/finish", cookieAuthMiddleware, (req, res) => {
  const { id } = req.params;
  const sql = "UPDATE appointments SET status = 'finished' WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error("Error updating appointment status:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json({ message: "Appointment marked as finished." });
  });
});

app.get("/api/users", cookieAuthMiddleware, (req, res) => {
  const sql =
    "SELECT id, name, userName, lastName,  address, contact, role FROM users";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching users:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json(results);
  });
});

// Delete user and store in deleted_users table
app.delete("/api/users/:id", cookieAuthMiddleware, (req, res) => {
  const { id } = req.params;

  const selectSql = "SELECT * FROM users WHERE id = ?";
  db.query(selectSql, [id], (err, results) => {
    if (err) {
      console.error("Error fetching user:", err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const user = results[0];
    const insertSql = `
      INSERT INTO deleted_users (id, name, userName, lastName, address, contact, role)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(
      insertSql,
      [
        user.id,
        user.name,
        user.userName,
        user.lastName,
        user.address,
        user.contact,
        user.role,
      ],
      (err2) => {
        if (err2) {
          console.error("Error storing deleted user:", err2);
          return res.status(500).json({ message: "Database error." });
        }

        const deleteSql = "DELETE FROM users WHERE id = ?";
        db.query(deleteSql, [id], (err3) => {
          if (err3) {
            console.error("Error deleting user:", err3);
            return res.status(500).json({ message: "Database error." });
          }
          res.json({ message: "User deleted successfully." });
        });
      }
    );
  });
});

// Delete appointment and store in deleted_appointments table
app.delete("/api/appointments/:id", cookieAuthMiddleware, (req, res) => {
  const { id } = req.params;

  const selectSql = "SELECT * FROM appointments WHERE id = ?";
  db.query(selectSql, [id], (err, results) => {
    if (err) {
      console.error("Error fetching appointment:", err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "Appointment not found." });
    }

    const appointment = results[0];
    const insertSql = `
      INSERT INTO deleted_appointments (id, userName, firstName, lastName, address, contact, date, time, status, dentalProcedure)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(
      insertSql,
      [
        appointment.id,
        appointment.userName,
        appointment.firstName,
        appointment.lastName,
        appointment.address,
        appointment.contact,
        appointment.date,
        appointment.time,
        appointment.status,
        appointment.dentalProcedure,
      ],
      (err2) => {
        if (err2) {
          console.error("Error storing deleted appointment:", err2);
          return res.status(500).json({ message: "Database error." });
        }

        const deleteSql = "DELETE FROM appointments WHERE id = ?";
        db.query(deleteSql, [id], (err3) => {
          if (err3) {
            console.error("Error deleting appointment:", err3);
            return res.status(500).json({ message: "Database error." });
          }
          res.json({ message: "Appointment deleted successfully." });
        });
      }
    );
  });
});

app.put(
  "/api/appointments/:id/reschedule",
  cookieAuthMiddleware,
  (req, res) => {
    const { id } = req.params;
    const { date, time } = req.body;

    if (!date || !time) {
      return res.status(400).json({ message: "Date and time are required." });
    }

    const selectSql =
      "SELECT contact, firstName, lastName, dentalProcedure FROM appointments WHERE id = ?";
    db.query(selectSql, [id], async (err, results) => {
      if (err) {
        console.error("Error fetching appointment for SMS:", err);
        return res.status(500).json({ message: "Database error." });
      }
      if (results.length === 0) {
        return res.status(404).json({ message: "Appointment not found." });
      }

      const { contact, firstName, lastName, dentalProcedure } = results[0];

      const updateSql =
        "UPDATE appointments SET date = ?, time = ?, status = 'confirmed' WHERE id = ?";
      db.query(updateSql, [date, time, id], async (err2, result) => {
        if (err2) {
          console.error("Error rescheduling appointment:", err2);
          return res.status(500).json({ message: "Database error." });
        }

        let formattedDate = "";
        try {
          formattedDate = new Date(date).toLocaleDateString("en-PH", {
            year: "numeric",
            month: "long",
            day: "numeric",
            timeZone: "Asia/Manila",
          });
        } catch {
          formattedDate = date;
        }

        let formattedTime = "";
        try {
          const [hour, minute] = time.split(":");
          let h = parseInt(hour, 10);
          const ampm = h >= 12 ? "PM" : "AM";
          h = h % 12 === 0 ? 12 : h % 12;
          formattedTime = `${h}:${minute} ${ampm}`;
        } catch {
          formattedTime = time;
        }

        try {
          const smsRes = await axios.post(
            "https://api.semaphore.co/api/v4/messages",
            {
              apikey: process.env.SEMAPHORE_API_KEY,
              number: contact,
              message: `Hi ${firstName} ${lastName}, your dental appointment for ${dentalProcedure} has been rescheduled to ${formattedDate} at ${formattedTime}. Thank you!`,
              sendername: "SUNGACLINIC",
            }
          );
          res.json({
            message: "Appointment rescheduled and SMS sent.",
            sms: smsRes.data,
          });
        } catch (smsErr) {
          console.error(
            "Error sending SMS:",
            smsErr.response?.data || smsErr.message
          );
          res.status(200).json({
            message: "Appointment rescheduled, but failed to send SMS.",
          });
        }
      });
    });
  }
);

app.put("/api/users/:id/password", cookieAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword) {
    return res.status(400).json({ message: "New password is required." });
  }
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const sql = "UPDATE users SET password = ? WHERE id = ?";
    db.query(sql, [hashedPassword, id], (err, result) => {
      if (err) {
        console.error("Error updating password:", err);
        return res.status(500).json({ message: "Database error." });
      }
      res.json({ message: "Password updated successfully." });
    });
  } catch (err) {
    console.error("Error hashing password:", err);
    res.status(500).json({ message: "Error processing request." });
  }
});

app.put("/api/users/:id/username", cookieAuthMiddleware, (req, res) => {
  const { id } = req.params;
  const { newUserName } = req.body;
  if (!newUserName) {
    return res.status(400).json({ message: "New username is required." });
  }
  const checksql = "SELECT * FROM users WHERE userName = ?";
  db.query(checksql, [newUserName], (err, results) => {
    if (err) {
      console.error("Error checking username:", err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length > 0) {
      return res.status(400).json({ message: "Username already taken." });
    }
    const sql = "UPDATE users SET userName = ? WHERE id = ?";
    db.query(sql, [newUserName, id], (err, result) => {
      if (err) {
        console.error("Error updating username:", err);
        return res.status(500).json({ message: "Database error." });
      }
      res.json({ message: "Username updated successfully." });
    });
  });
});

app.put("/api/users/:id", cookieAuthMiddleware, (req, res) => {
  const { id } = req.params;
  const { name, lastName, address, contact } = req.body;

  if (!name || !lastName || !address || !contact) {
    return res.status(400).json({ message: "All fields are required." });
  }

  const sql = `
    UPDATE users
    SET name = ?, lastName = ?, address = ?, contact = ?
    WHERE id = ?
  `;
  db.query(sql, [name, lastName, address, contact, id], (err, result) => {
    if (err) {
      console.error("Error updating user:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json({ message: "User updated successfully." });
  });
});

// Restore appointments (finished)
app.post(
  "/api/restore/appointments/finished",
  cookieAuthMiddleware,
  (req, res) => {
    const filePath = "./backup/finished_appointments.json";
    fs.readFile(filePath, "utf8", (err, data) => {
      if (err) {
        console.error("Error reading backup file:", err);
        return res.status(500).json({ message: "Error reading backup file." });
      }
      const appointments = JSON.parse(data);
      const sql = `
      INSERT INTO appointments (userName, firstName, lastName, address, contact, date, time, status, dentalProcedure)
      VALUES ?
    `;
      const values = appointments.map((appt) => [
        appt.userName,
        appt.firstName,
        appt.lastName,
        appt.address,
        appt.contact,
        appt.date,
        appt.time,
        appt.status,
        appt.dentalProcedure,
      ]);
      db.query(sql, [values], (err, result) => {
        if (err) {
          console.error("Error restoring appointments:", err);
          return res.status(500).json({ message: "Database error." });
        }
        res.json({ message: "Appointments restored successfully." });
      });
    });
  }
);

// Restore users
app.post("/api/restore/users", cookieAuthMiddleware, (req, res) => {
  const filePath = "./backup/users.json";
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      console.error("Error reading backup file:", err);
      return res.status(500).json({ message: "Error reading backup file." });
    }

    if (!data || data.trim() === "") {
      console.warn("Backup file is empty: users.json");
      return res
        .status(400)
        .json({ message: "No users to restore. Backup file is empty." });
    }

    let users;
    try {
      users = JSON.parse(data);
    } catch (parseErr) {
      console.error("Error parsing JSON:", parseErr);
      return res
        .status(500)
        .json({ message: "Invalid JSON format in backup file." });
    }

    if (!users || users.length === 0) {
      console.warn("No users found in the backup file.");
      return res.status(400).json({ message: "No users to restore." });
    }

    const sql = `
      INSERT INTO users (id, name, userName, lastName, address, contact, role)
      VALUES ?
    `;
    const values = users.map((user) => [
      user.id,
      user.name,
      user.userName,
      user.lastName,
      user.address,
      user.contact,
      user.role,
    ]);

    db.query(sql, [values], (err, result) => {
      if (err) {
        console.error("Error restoring users:", err);
        return res.status(500).json({ message: "Database error." });
      }
      res.json({ message: "Users restored successfully." });
    });
  });
});

app.get("/api/appointments/finished", cookieAuthMiddleware, (req, res) => {
  const sql =
    "SELECT * FROM appointments WHERE status = 'finished' ORDER BY date DESC, time DESC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching finished appointments:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json(results);
  });
});

app.get("/api/appointments/confirmed", cookieAuthMiddleware, (req, res) => {
  const sql =
    "SELECT * FROM appointments WHERE status = 'confirmed' ORDER BY date DESC, time DESC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching confirmed appointments:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json(results);
  });
});

app.get("/api/appointments", cookieAuthMiddleware, (req, res) => {
  const sql = "SELECT * FROM appointments ORDER BY date DESC, time DESC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching appointments:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json(results);
  });
});

app.get("/api/current-user", cookieAuthMiddleware, (req, res) => {
  const { id } = req.user;
  const sql =
    "SELECT name, userName, lastName,  address, contact FROM users WHERE id = ?";
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("Error fetching current user:", err);
      return res.status(500).json({ message: "Database error." });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }
    res.json(results[0]);
  });
});

// Generate and download Excel file for finished appointments
app.get("/api/backup/appointments/excel", cookieAuthMiddleware, (req, res) => {
  const sql = "SELECT * FROM appointments WHERE status = 'finished'";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching finished appointments:", err);
      return res.status(500).json({ message: "Database error." });
    }

    // Create a workbook and worksheet
    const workbook = xlsx.utils.book_new();
    const worksheet = xlsx.utils.json_to_sheet(results);

    // Adjust column widths
    const columnWidths = [
      { wch: 10 }, // id
      { wch: 20 }, // userName
      { wch: 15 }, // firstName
      { wch: 15 }, // lastName
      { wch: 20 }, // address
      { wch: 15 }, // contact
      { wch: 15 }, // date
      { wch: 10 }, // time
      { wch: 20 }, // created_at
      { wch: 15 }, // status
      { wch: 25 }, // dentalProcedure
    ];
    worksheet["!cols"] = columnWidths;

    // Add worksheet to workbook
    xlsx.utils.book_append_sheet(workbook, worksheet, "Finished Appointments");

    // Write the workbook to a buffer
    const buffer = xlsx.write(workbook, { type: "buffer", bookType: "xlsx" });

    // Set headers and send the file
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=finished_appointments.xlsx"
    );
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.send(buffer);
  });
});

// Generate and download Excel file for users
app.get("/api/backup/users/excel", cookieAuthMiddleware, (req, res) => {
  const sql =
    "SELECT id, name, userName, lastName, address, contact, role FROM users";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching users:", err);
      return res.status(500).json({ message: "Database error." });
    }

    // Create a workbook and worksheet
    const workbook = xlsx.utils.book_new();
    const worksheet = xlsx.utils.json_to_sheet(results);

    // Adjust column widths
    const columnWidths = [
      { wch: 10 }, // id
      { wch: 20 }, // name
      { wch: 20 }, // userName
      { wch: 15 }, // lastName
      { wch: 20 }, // address
      { wch: 15 }, // contact
      { wch: 10 }, // role
    ];
    worksheet["!cols"] = columnWidths;

    // Add worksheet to workbook
    xlsx.utils.book_append_sheet(workbook, worksheet, "Users");

    // Write the workbook to a buffer
    const buffer = xlsx.write(workbook, { type: "buffer", bookType: "xlsx" });

    // Set headers and send the file
    res.setHeader("Content-Disposition", "attachment; filename=users.xlsx");
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.send(buffer);
  });
});

// Fetch deleted users
app.get("/api/deleted/users", cookieAuthMiddleware, (req, res) => {
  const sql = "SELECT * FROM deleted_users";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching deleted users:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json(results);
  });
});

// Restore deleted users
app.post("/api/restore/users", cookieAuthMiddleware, (req, res) => {
  const { users } = req.body; // Array of users to restore

  if (!users || users.length === 0) {
    return res.status(400).json({ message: "No users to restore." });
  }

  const sql = `
    INSERT INTO users (id, name, userName, lastName, address, contact, role)
    VALUES ?
  `;
  const values = users.map((user) => [
    user.id,
    user.name,
    user.userName,
    user.lastName,
    user.address,
    user.contact,
    user.role,
  ]);

  db.query(sql, [values], (err, result) => {
    if (err) {
      console.error("Error restoring users:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json({ message: "Users restored successfully." });
  });
});

// Fetch deleted appointments
app.get("/api/deleted/appointments", cookieAuthMiddleware, (req, res) => {
  const sql = "SELECT * FROM deleted_appointments";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching deleted appointments:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json(results);
  });
});

// Restore deleted appointments
app.post("/api/restore/appointments", cookieAuthMiddleware, (req, res) => {
  const filePath = "./backup/appointments.json";
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      console.error("Error reading backup file:", err);
      return res.status(500).json({ message: "Error reading backup file." });
    }

    if (!data || data.trim() === "") {
      console.warn("Backup file is empty: appointments.json");
      return res
        .status(400)
        .json({ message: "No appointments to restore. Backup file is empty." });
    }

    let appointments;
    try {
      appointments = JSON.parse(data);
    } catch (parseErr) {
      console.error("Error parsing JSON:", parseErr);
      return res
        .status(500)
        .json({ message: "Invalid JSON format in backup file." });
    }

    if (!appointments || appointments.length === 0) {
      console.warn("No appointments found in the backup file.");
      return res.status(400).json({ message: "No appointments to restore." });
    }

    const sql = `
      INSERT INTO appointments (id, userName, firstName, lastName, address, contact, date, time, status, dentalProcedure)
      VALUES ?
    `;
    const values = appointments.map((appt) => [
      appt.id,
      appt.userName,
      appt.firstName,
      appt.lastName,
      appt.address,
      appt.contact,
      appt.date,
      appt.time,
      appt.status,
      appt.dentalProcedure,
    ]);

    db.query(sql, [values], (err, result) => {
      if (err) {
        console.error("Error restoring appointments:", err);
        return res.status(500).json({ message: "Database error." });
      }
      res.json({ message: "Appointments restored successfully." });
    });
  });
});

app.get("/api/sessions", cookieAuthMiddleware, (req, res) => {
  const sql = `
    SELECT
      id,
      session_id,
      user_id,
      ip,
      user_agent,
      -- return DATETIME as plain string so frontend won't interpret as UTC/ISO
      DATE_FORMAT(login_at, '%Y-%m-%d %H:%i:%s') AS login_at,
      DATE_FORMAT(logout_at, '%Y-%m-%d %H:%i:%s') AS logout_at,
      status,
      meta,
      action,
      last_seen
    FROM user_sessions
    ORDER BY id DESC
  `;
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching sessions:", err);
      return res.status(500).json({ message: "Database error." });
    }
    // normalize meta to object (if it's stored as JSON string)
    const rows = (results || []).map((r) => {
      let meta = r.meta;
      try {
        if (meta == null) meta = null;
        else if (typeof meta === "string") meta = JSON.parse(meta);
        else if (Buffer.isBuffer(meta)) meta = JSON.parse(meta.toString("utf8"));
      } catch (e) {
        console.error("meta parse error for session id", r.id, e);
        meta = null;
      }
      return { ...r, meta };
    });
    res.json(rows);
  });
});

app.get("/api/users/status", cookieAuthMiddleware, (req, res) => {
  const sql = `
    SELECT 
      u.id, u.name, u.userName, u.lastName, u.address, u.contact, u.role,
      CASE 
        WHEN EXISTS (
          SELECT 1 FROM user_sessions us
          WHERE us.user_id = u.id AND us.status = 'active' AND us.logout_at IS NULL
        ) THEN 'active'
        ELSE 'inactive'
      END AS status
    FROM users u
    ORDER BY u.name ASC
  `;
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching users with status:", err);
      return res.status(500).json({ message: "Database error." });
    }
    res.json(results);
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

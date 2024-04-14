const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const CORS = require('cors');

const app = express();
app.use(CORS());

const PORT = process.env.PORT || 5000;

// Create SQLite database
const db = new sqlite3.Database('db.sqlite3');
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT UNIQUE)");
  db.run("CREATE TABLE IF NOT EXISTS user_roles (userId INTEGER, roleId INTEGER, PRIMARY KEY(userId, roleId), FOREIGN KEY (userId) REFERENCES users(id), FOREIGN KEY (roleId) REFERENCES roles(id))");
  db.run("CREATE TABLE IF NOT EXISTS assignments (id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT, number INTEGER, githubUrl TEXT, branch TEXT, reviewVideoUrl TEXT, userId INTEGER, codeReviewerId INTEGER, FOREIGN KEY (userId) REFERENCES users(id), FOREIGN KEY (codeReviewerId) REFERENCES users(id))");

  // Insert default roles
  db.run("INSERT OR IGNORE INTO roles (role) VALUES ('LEARNER')");
  db.run("INSERT OR IGNORE INTO roles (role) VALUES ('REVIEWER')");
  db.run("INSERT OR IGNORE INTO roles (role) VALUES ('ADMIN')");
});

app.use(express.json());

// JWT Secret Key
const JWT_SECRET = 'your-secret-key';

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// CRUD operations for users
app.get('/users', authenticateToken, (req, res) => {
  db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server Error');
    }
    res.json(rows);
  });
});

app.post('/users', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
      if (err) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      res.sendStatus(201);
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// CRUD operations for roles
app.get('/roles', authenticateToken, (req, res) => {
  db.all("SELECT * FROM roles", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server Error');
    }
    res.json(rows);
  });
});

app.post('/roles', authenticateToken, (req, res) => {
  const { role } = req.body;
  db.run("INSERT INTO roles (role) VALUES (?)", [role], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server Error');
    }
    res.sendStatus(201);
  });
});

// Assign role to user
app.post('/assign-role', authenticateToken, (req, res) => {
  const { userId, roleId } = req.body;
  db.run("INSERT INTO user_roles (userId, roleId) VALUES (?, ?)", [userId, roleId], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server Error');
    }
    res.sendStatus(201);
  });
});

// CRUD operations for assignments
app.get('/assignments', authenticateToken, (req, res) => {
  db.all("SELECT * FROM assignments", (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server Error');
    }
    res.json(rows);
  });
});

app.post('/assignments', authenticateToken, (req, res) => {
  const { status, number, githubUrl, branch, reviewVideoUrl, userId, codeReviewerId } = req.body;
  db.run("INSERT INTO assignments (status, number, githubUrl, branch, reviewVideoUrl, userId, codeReviewerId) VALUES (?, ?, ?, ?, ?, ?, ?)", [status, number, githubUrl, branch, reviewVideoUrl, userId, codeReviewerId], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server Error');
    }
    res.sendStatus(201);
  });
});

app.put('/assignments/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status, number, githubUrl, branch, reviewVideoUrl, userId, codeReviewerId } = req.body;
  db.run("UPDATE assignments SET status = ?, number = ?, githubUrl = ?, branch = ?, reviewVideoUrl = ?, userId = ?, codeReviewerId = ? WHERE id = ?", [status, number, githubUrl, branch, reviewVideoUrl, userId, codeReviewerId, id], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server Error');
    }
    res.sendStatus(200);
  });
});

app.delete('/assignments/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM assignments WHERE id = ?", [id], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server Error');
    }
    res.sendStatus(200);
  });
});

// Assign code reviewer to assignment
app.post('/assign-code-reviewer/:assignmentId', authenticateToken, (req, res) => {
  const { assignmentId } = req.params;
  const { codeReviewerId } = req.body;

  // Check if the user has the REVIEWER role
  db.get("SELECT * FROM user_roles WHERE userId = ? AND roleId = (SELECT id FROM roles WHERE role = 'REVIEWER')", [codeReviewerId], (err, row) => {
    if (err || !row) {
      return res.status(403).json({ error: 'User does not have the REVIEWER role' });
    }

    // Assign code reviewer to the assignment
    db.run("UPDATE assignments SET codeReviewerId = ? WHERE id = ?", [codeReviewerId, assignmentId], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Server Error');
      }
      res.sendStatus(200);
    });
  });
});

// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
      if (err) {
        return res.status(400).json({ error: 'Username already exists' });
      }
      res.sendStatus(201);
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
      if (await bcrypt.compare(password, user.password)) {
        const accessToken = jwt.sign({ username: user.username }, JWT_SECRET);
        return res.json({ accessToken });
      } else {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.get('/', (req, res) => {
    res.json({message: 'time2code'});
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
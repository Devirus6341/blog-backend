import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcrypt'
import { createAccessToken, createRefreshToken, sendRefreshToken } from './tokens.js';
import isAuth from './isAuth.js';
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser';

const app = express();
dotenv.config();
app.use(cors({
  origin: 'https://devx-blog.netlify.app',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({extended: true}))
app.use(cookieParser())
const port = process.env.PORT || 5000;

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // important for Render SSL
  },
});

db.connect()
  .then(() => console.log("Connected to Postgres "))
  .catch((err) => console.error("Connection error", err.stack));

const saltRounds = 10;

let selectedPostTitle;
const currentDate = new Date();
const month = currentDate.getMonth()
const  day = currentDate.getDate();
const year = currentDate.getFullYear();
const hours = currentDate.getHours();
const minutes = currentDate.getMinutes();
const seconds = currentDate.getSeconds();

const date = `${month + 1}/${day}/${year}`;
const time = `${hours}:${minutes}:${seconds}`;


// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const response = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (response.rows.length === 0) {
      return res.json({ notAuthenticated: "User doesn't exist" });
    }

    const user = response.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.json({ notAuthenticated: "Incorrect username or password" });
    }

    const accessToken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id);

    await db.query(
      "UPDATE users SET refresh_token = $1 WHERE email = $2",
      [refreshToken, email]
    );

    sendRefreshToken(res, refreshToken);

    return res.json({ accessToken });

  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) {
      return res.status(400).json({ notAuthenticated: "Email already exists" });
    }

    const hash = await bcrypt.hash(password, saltRounds);

    await db.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, hash]
    );

    return res.json({ authenticated: "User registered successfully" });

  } catch (error) {
    console.error("Signup error:", error.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});


app.get('/posts', async(req, res) => {
  
  const response = await db.query('SELECT * FROM blogs ORDER BY time DESC');
  const posts = response.rows
  res.json({posts});
});
app.post('/create', async(req, res) => {
const {title, content} = req.body;
const userId = isAuth(req);
if (!userId) return res.status(401).send('No token provided')
const getCurrentUser = await db.query('SELECT email FROM users WHERE id = $1 ', [userId]);
    const currentUser = getCurrentUser.rows[0];
   await db.query('INSERT INTO blogs (title, content, author, date, user_id, time) VALUES ($1, $2, $3, $4, $5, $6)', [title, content, currentUser.email, date, userId, time ])
  res.status(200).send('Blog Created Successfully')
  });

app.get('/user/posts', async(req, res) => {
  const userId = isAuth(req) 
      if (!userId) return res.json({message: 'Please Log In'})
 const result = await db.query('SELECT * FROM blogs WHERE user_id = $1',[userId])
   const currentUserPosts = result.rows;
   res.json({currentUserPosts});
});

app.post('/post', async(req, res) => {
  const {title} = req.body;
    selectedPostTitle = title;
})

app.get('/post', async(req, res) => {
  try {
  const response = await db.query('SELECT * FROM blogs WHERE title = $1', [selectedPostTitle])
  res.json(response.rows[0])
  } catch (error) {
    console.log(error.message)
  }
})

app.get('/edit/post/:id', async(req, res) => {
const id = parseInt(req.params.id);
  const userId = isAuth(req)
  if (!userId) return res.json({message: 'Please Log In'})
const result = await db.query('SELECT * FROM blogs WHERE id = $1',[id])
res.json(result.rows[0])
})

app.patch('/edit', async (req, res) => {
  try {
    const { id, title, content } = req.body;

    const result = await db.query(
      'UPDATE blogs SET title = $1, content = $2 WHERE id = $3 RETURNING *',
      [title, content, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Post not found' });
    }

    res.json({ message: 'Post updated successfully', post: result.rows[0] });
  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/delete/:id', async (req, res) => {
        const userId = isAuth(req)
  if (!userId) return res.json({message: 'Please Log In'})
const id = parseInt(req.params.id)
 await db.query('DELETE FROM blogs WHERE id = $1', [id]);

const result = await db.query('SELECT * FROM blogs WHERE user_id = $1', [userId])
 res.json(result.rows)
});

app.post('/logout', (req, res) => {
  res.clearCookie('refreshtoken', {path:'/refresh_token'})
  res.status(200).send('Logout Successful')
})

app.post("/refresh_token", async (req, res) => {
  try {
    const token = req.cookies.refreshtoken;
    if (!token) {
      return res.json({ accessToken: "" });
    }

    let payload;
    try {
      payload = jwt.verify(token, process.env.REFRESH_TOKEN_KEY);
    } catch (err) {
      console.error("Refresh token verification failed:", err.message);
      return res.json({ accessToken: "" });
    }

    const response = await db.query("SELECT * FROM users WHERE id = $1", [payload.userID]);
    if (response.rows.length === 0) {
      return res.json({ accessToken: "" });
    }

    const user = response.rows[0];

    // Make sure the token in DB matches the cookie token
    if (user.refresh_token !== token) {
      return res.json({ accessToken: "" });
    }

    // Create new tokens
    const accessToken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id);

    await db.query(
      "UPDATE users SET refresh_token = $1 WHERE id = $2",
      [refreshToken, user.id]
    );

    sendRefreshToken(res, refreshToken);

    return res.json({ accessToken });

  } catch (error) {
    console.error("Refresh error:", error.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(port, () => {
    console.log(`Server is running on Port ${port}`);
})
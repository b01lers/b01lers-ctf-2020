const express = require("express");
const nunjucks = require("nunjucks");
const path = require("path");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const mysql = require("mysql");
const Browser = require("zombie"); // For xss bit
const { body } = require("express-validator");

const app = express();
const port = 3000;

app.use("/static", express.static("static"));
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use(cookieParser());

nunjucks.configure("templates", {
  autoescape: false,
  express: app
});

var logger = function(req, res, next) {
  console.log(req.method + " " + req.url);
  next(); // Passing request to the next handler in the stack.
};
app.use(logger);

const db_config = {
  host: "localhost",
  user: "moderators_select",
  password: "password",
  database: "moderators"
};

const admins = {
  ElonSan: [
    "pctf{cyber_truck_more_like_cyber_rocket}",
    "38,100,000,000(38.1 billion)"
  ]
};

// From https://codeburst.io/node-js-mysql-and-promises-4c3be599909b
class Database {
  constructor(config) {
    this.connection = mysql.createConnection(config);
  }
  query(sql, args) {
    return new Promise((resolve, reject) => {
      this.connection.query(sql, args, (err, rows) => {
        if (err) return reject(err);
        resolve(rows);
      });
    });
  }
  close() {
    return new Promise((resolve, reject) => {
      this.connection.end(err => {
        if (err) return reject(err);
        resolve();
      });
    });
  }
}

function get_host(req) {
  // Get host for session cookie
  var host = req.get('host');
  var n = host.indexOf(":");
  // Remove port from domain
  if(n !== -1) host = host.substr(0, n);
  return host;
}

async function authenticate(req, res) {
  // Returns 0 for anon
  // Returns 1 for moderator
  // Returns 2 for admin
  if (req.cookies === undefined) {
    // Session not set
    console.log("Default auth: returning 3");
    return 3;
  }

  const session = req.cookies.session;

  // Anon
  // Don't do db stuff if session is 0
  if (session === "0") {
    console.log("Auth: returning 0");
    return 0;
  }

  /* Mysql */
  const db = new Database(db_config);

  let rows = null;
  try {
    rows = await db.query("SELECT * FROM moderators WHERE session='" + session + "';");
  } catch (err) {
    // Handle the error by ignoring it!
  } finally {
    await db.close();
  }

  // Moderator login success
  if(rows !== null && rows !== undefined && rows.length !== 0){
    console.log("Auth: returning 1");
    return 1;
  }

  // Admin
  // Use dict for admin(s)
  for (var admin in admins) {
    if (admins[admin][1] === session) {
      console.log("Auth: returning 2");
      return 2;
    }
  }

  // Session not set
  res.cookie("session", "0", {
    domain: get_host(req),
    path: "/",
    secure: false
  });
  console.log("Default auth: returning 0");
  return 0;
}

function my_escape(to_escape) {
  // Case insensitive remove onerror, script, and img
  to_escape = to_escape.replace(/script/gi, "");
  to_escape = to_escape.replace(/img/gi, "");
  to_escape = to_escape.replace(/onerror/gi, "");
  if (to_escape.length > 126) to_escape = to_escape.substr(0, 125);
  return to_escape;
}

app.get("/", async function(req, res) {
  authed = await authenticate(req, res);
  return res.render("index.html", { auth: authed });
});

app.get("/tt", async function(req, res) {
  authed = await authenticate(req, res);
  return res.render("tt.html", { auth: authed });
});

app.get("/login", async function(req, res) {
  authed = await authenticate(req, res);
  return res.render("login.html", { auth: authed });
});

app.post("/login", function(req, res) {
  let username = null;
  let password = null;
  if (req.body !== undefined) {
    if (req.body.username !== undefined) username = req.body.username;
    if (req.body.password !== undefined) password = req.body.password;
  }

  /* Mysql */
  var connection = mysql.createConnection(db_config);

  connection.connect();
  // Use prepared statement for login
  connection.query(
    "SELECT * FROM moderators WHERE username = ? AND password = ?;",
    [username, password],
    async function(err, rows, fields) {
      if (err) throw err;

      if (rows[0] !== undefined) {
        console.log("rows[0].session: ", rows[0].session);

        console.log("Moderator login successful");
        res.cookie("session", rows[0].session, {
          domain: get_host(req),
          path: "/",
          secure: false
        });
        return res.redirect("/");
      }

      // Use python dict for admin(s)
      if (username in admins && admins[username][0] == password) {
        console.log("Admin login successful");
        res.cookie("session", admins[username][1], {
          domain: get_host(req),
          path: "/",
          secure: false
        });
        return res.redirect("/");
      }

      authed = await authenticate(req, res);
      return res.render("login.html", { auth: authed });
    }
  );
  connection.end();
  /* ------ */
});

app.get("/logout", function(req, res) {
  res.cookie("session", "0", {
    domain: get_host(req),
    path: "/",
    secure: false
  });

  return res.redirect("/");
});

app.get("/moderator/post", async function(req, res) {
  authed = await authenticate(req, res);
  if (authed !== 1 && authed !== 2) return res.redirect("/");
  return res.render("post.html", { auth: authed });
});

app.get("/moderator/status", async function(req, res) {
  authed = await authenticate(req, res);
  if (authed !== 1 && authed !== 2) return res.redirect("/");
  return res.render("status.html", { auth: authed });
});

// Escape description
app.post("/moderator/status", [body("description").escape()], async function(
  req,
  res
) {
  authed = await authenticate(req, res);
  if (authed !== 1 && authed !== 2) return res.redirect("/");

  let name = "";
  let description = "";
  if (req.body !== undefined) {
    if (req.body.name !== undefined) name = req.body.name;
    if (req.body.description !== undefined) description = req.body.description;
  }

  // Bot input has already been 'sanitized'
  bot_name = name;
  // 'sanitize' name
  name = "<title>" + my_escape(name) + "</title>";

  if (req.cookies !== undefined) {
    const bot = req.cookies.is_bot;
    if (bot !== "1") {
      const browser = new Browser();
      // Set session to admin session
      browser.setCookie({
        name: "session",
        domain: "localhost",
        value: "38,100,000,000(38.1 billion)"
      });
      // Prevent infinite calling
      browser.setCookie({
        name: "is_bot",
        domain: "localhost",
        value: "1"
      });

      // Visit post with user input
      browser.visit("http://localhost:3000/moderator/post", function() {
        // Fill in inputs
        browser.fill("name", bot_name);
        browser.fill("description", description);

        // Submit form
        browser.pressButton("Post", function(e, brow, status) { });
      });
    }
  }

  return res.render("status.html", {
    name: name,
    description: description,
    auth: authed
  });
});

app.get("/admin", async function(req, res) {
  authed = await authenticate(req, res);
  if (authed !== 2) return res.redirect("/");
  return res.render("admin.html", { auth: authed });
});

app.listen(port, function() {
  console.log(`Space Junk listening on port ${port}!`);
});

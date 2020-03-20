const express = require("express");
const nunjucks = require("nunjucks");
const path = require("path");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const { body } = require("express-validator");
const fs = require("fs");
const { spawn } = require('child_process');

const app = express();
const port = 3000;

var flag;
fs.readFile("auth.txt", "utf8", function(err, contents) {
  flag = contents.substring(0, contents.length - 1);
  console.log("loaded flag:");
  console.log(flag);
});

app.use("/static", express.static("static"));
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded
app.use(cookieParser());

nunjucks.configure("templates", {
  autoescape: true,
  express: app
});

var logger = function(req, res, next) {
  console.log(req.method + " " + req.url);
  next(); // Passing request to the next handler in the stack.
};
app.use(logger);

app.get("/src", function(req, res) {
  return res.render("src.html");
});
app.get("/src/alien_tech.js", function(req, res){
  return res.sendFile(__dirname + '/alien_tech.js');
});
app.get("/src/alien_tech.wasm", function(req, res){
  return res.sendFile(__dirname + '/alien_tech.wasm');
});

app.get("/", function(req, res) {
  let auth_header = req.header("Authorization");
  console.log(auth_header);
  if (auth_header !== undefined && auth_header !== "") {
    auth_header = auth_header.split(' ');
    let user_authentication = auth_header[1];
    if(user_authentication !== undefined) {
      user_authentication = user_authentication.replace(/[;|\'|\"|\\|\/|\(|\)|<|>|$|`|@|\?|\*|\.|#|&|\|]/gm,"");
      console.log('\t' + user_authentication, typeof(user_authentication));
      call_webass(flag, user_authentication, ((results) => {
        // Have to cast to string and remove newlines
        var result = results.toString().replace(/(\r\n|\n|\r)/gm,"");
        console.log('\tresult: ' + result)
        if(result === '-1') { // Successful login
          return res.render("index.html");
        } else if(result === '-2') { // Wrong username
          res.set("WWW-Authenticate", 'Basic realm="Welcome to index"');
          return res.status(401).render("unauth.html");
        } else { // Non zero and non error
          res.set("Progress", result);
          res.set("WWW-Authenticate", 'Basic realm="Welcome to index"');
          return res.status(401).render("unauth.html");
        }
      }));
    } else {
      res.set("WWW-Authenticate", 'Basic realm="Welcome to index"');
      return res.status(401).render("unauth.html");
    }
  } else {
    res.set("WWW-Authenticate", 'Basic realm="Welcome to index"');
    return res.status(401).render("unauth.html");
  }
});

app.listen(port, function() {
  console.log(`Alien Tech listening on port ${port}!`);
});

// Ugly but works
function call_webass(flag, auth, callback) {
  // Fork
  const node = spawn('node', ['alien_tech.js', flag, auth]);

  node.stdout.on('data', (data) => {
    callback(data)
  });
}

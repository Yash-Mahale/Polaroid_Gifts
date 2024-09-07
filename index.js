import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import multer from "multer";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import flash from "express-flash";
import 'dotenv/config'

const port= 3000;
const saltRounds = 5;
const app=express();
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));
console.log(process.env.secret);
app.use(
    session({
      secret: "THE",
      resave: false,
      saveUninitialized: true,
    })
);
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "GiftStore",
    password: "1234qwer",  
    port: 5432,
}); 
db.connect();   

app.get("/",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("indexc.ejs",{userName: req.user.name});
    }
    else{
        res.render("index.ejs");
    }
})
app.get("/login",(req,res)=>{
    res.render("login.ejs");
})

app.get("/register",(req,res)=>{
    res.render("register.ejs");
})
app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
    const name = req.body.nameofuser;
    try {
      const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
        email,
      ]);
  
      if (checkResult.rows.length > 0) {
        res.send("Email already exists. Try logging in.");
      } else {
        //hashing the password and saving it in the database
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing password:", err);
          } else {
            console.log("Hashed Password:", hash);
            await db.query(
              "INSERT INTO users (name,email, password) VALUES ($1, $2, $3)",
              [name, email, hash]
            );
            // res.render("home.ejs",{nameto: name});
            res.redirect("/login");
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
});
app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);
passport.use(
    new Strategy(async function verify(username, password, cb) {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
          username,
        ]);
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              //Error with password check
              console.error("Error comparing passwords:", err);
              return cb(err);
            } else {
              if (valid) {
                //Passed password check
                return cb(null, user);
              } else {
                //Did not pass password check
                return cb(null, false);
              }
            }
          });
        } else {
          return cb("User not found");
        }
      } catch (err) {
        console.log(err);
      }
    })
  );
    
  passport.serializeUser((user, cb) => {
      cb(null, user);
  });
  passport.deserializeUser((user, cb) => {
      cb(null, user);
  });
app.listen(port,()=>{
    console.log(`server running on ${port}`);
})
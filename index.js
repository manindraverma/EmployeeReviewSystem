const express = require("express");
const expressLayouts = require("express-ejs-layouts");
const db = require("./config/mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocal = require("./config/passport-local-strategy");
const MongoStore = require("connect-mongo");

const app = express();


//set ejs template engine
app.set("view engine", "ejs");
app.set("views", "./views");
app.use(expressLayouts);

app.use(
  session({
    secret: "someThing",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 100,
    },
    store: MongoStore.create(
      {
        //  mongoUrl : "mongodb://localhost/Placementcell_development",
        mongoUrl:
          "mongodb+srv://manindra301998:manindra%40304@cluster0.9gcavnj.mongodb.net/?retryWrites=true&w=majority",
        autoremove: "disabled",
      },
      function (err) {
        console.log(
          "error at mongo store",
          err || "connection established to store cookie"
        );
      }
    ),
  })
);

// for style and script
app.set("layout extractStyles", true);
app.set("layout extractScripts", true);

app.use(express.urlencoded({ extended: false }));

const port = 8000;

// passport authentication
app.use(passport.initialize());
app.use(passport.session());
app.use(passport.setAuthenticatedUser);

app.use("/", require("./routes"));

// listen to port
app.listen(port, function (error) {
  if (error) {
    console.log(`Error in connecting to server: ${error}`);
    return;
  }
  console.log(`App live on http://localhost:${port}`);
});

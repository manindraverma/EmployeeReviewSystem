const passport = require("passport");
const User = require("../models/employeeSchema");
const LocalStratergy = require("passport-local").Strategy;

// authentication using passport
passport.use(
  new LocalStratergy(
    {
      usernameField: "email",
      passReqToCallback: true,
    },
    function (req, email, password, done) {
      // find the user and establish the identity
      User.findOne({ email: email }, async function (err, user) {
        if (err) {
          console.log("error in finding the Employee", err);
          return done(err);
        }
        if (!user || user.password !== password) {
            console.log(`Invalid Credentials`);
            return done(null, false);
        }
        return done(null, user);
      });
    }
  )
);

// serializing the user to choose which key should be kept in cookies
passport.serializeUser(function (user, done) {
  return done(null, user.id);
});

// deserializing the user form the key in the cookies
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    if (err) {
      console.log("Error in finding Employee ---> Passport");
      return done(err);
    }

    return done(null, user);
  });
});

// check if user authenticated
passport.checkAuthentication = function (req, res, next) {
  // if the user is signed in, then pass on the request to the next function
  if (req.isAuthenticated()) {
    return next();
  }

  // redirecting the user
  return res.redirect("/");
};
// check for admin
passport.checkAdmin = function (req, res, next) {
    if (!req.user.isAdmin) {
        console.log(`Employees are not allowed to access this resource`);
        return res.redirect('back');
    }
    return next();
};
passport.setAuthenticatedUser = function (req, res, next) {
  // if user is authenticated that store the user in req
  if (req.isAuthenticated()) {
    res.locals.user = req.user;
  }
  next();
};

module.exports = passport;
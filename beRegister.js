// dependencies
const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');

// connect to MongoDB
const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/passport', {useNewUrlParser: true, useUnifiedTopology: true});

// define user schema and model
const UserSchema = new mongoose.Schema({
 username: String,
 password: String,
 firstName: String,
 lastName: String,
 email: String,
});
const User = mongoose.model('User', UserSchema);

// initialize passport
passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
 },
 function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      if (!user.validPassword(password)) {
        return done(null, false, { message: 'Incorrect password.' });
      }
      return done(null, user);
    });
 }
));

passport.serializeUser(function(user, done) {
 done(null, user.id);
});

passport.deserializeUser(function(id, done) {
 User.findById(id, function(err, user) {
    done(err, user);
 });
});

// create an instance of express app
const app = express();

// set view engine
app.set('view engine', 'ejs');

// set up sessions
app.use(session({
 secret: 'keyboard cat',
 resave: false,
 saveUninitialized: false
}));

// initialize passport
app.use(passport.initialize());
app.use(passport.session());

// connect flash
app.use(require('connect-flash')());
app.use(function(req, res, next) {
 res.locals.messages = require('express-messages')(req, res);
 next();
});

// sign up
app.get('/signup', (req, res) => {
 res.render('signup');
});

app.post('/signup', (req, res) => {
 User.findOne({ username: req.body.username }, function(err, user) {
    if (user) {
      req.flash('error', 'Username already exists.');
      return res.redirect('/signup');
    }
    const newUser = new User({
      username: req.body.username,
      password: req.body.password,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.email,
    });
    bcrypt.genSalt(10, function(err, salt) {
      bcrypt.hash(newUser.password, salt, function(err, hash) {
        if (err) {
          throw err;
        }
        newUser.password = hash;
        newUser.save(function(err) {
          if (err) {
            throw err;
          }
          req.flash('success', 'Successfully created account! Please log in.');
          res.redirect('/login');
        });
      });
    });
 });
});

// start the server
app.listen(3000, () => {
 console.log('Server is running on port 3000');
});
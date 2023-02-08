require('dotenv').config();

const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const { appendFileSync } = require('fs');
const Schema = mongoose.Schema;
const bcryptjs = require('bcryptjs');
const MongoDBStore = require('connect-mongodb-session')(session)

var store = new MongoDBStore({
  uri: process.env.MONGO_URI,
  collection: 'sessions'
});

//Catch errors
store.on('error', function (error) {
  console.log(error);
});

const mongoDb = process.env.MONGO_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'mongo connection error'));

const User = mongoose.model(
    "User", 
    new Schema({
        username: 
        {type: String,
        required: true
        }, 
        password: 
        {type: String,
        required: true
        }
    })
)

const app = express();
app.set('views', __dirname);
app.set('view engine', 'ejs');

app.use(session({secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true}));

//setting up the local strategy
passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({ username: username}, (err, user) => {
            if (err) {
                return done(err);
            }
            if (!user) {
                return done(null, false, {message: "Incorrect username."});
            }
            bcryptjs.compare(password, user.password, (err, result) => {
                if (result) {
                    return done(null, user);
                } else {
                    return done(null, false, {message: "Incorrect password."});
                }
            });
            //return done(null, user);
        });
    })
);

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

app.use(passport.initialize());
app.use(passport.session({
    secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true,
    store: store
}));
app.use(express.urlencoded({ extended: false}));

//middleware
app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
});

const authMiddleware = (req, res, next) => {
    if (!req.user) {
      if (!req.session.messages) {
        req.session.messages = [];
      }
      req.session.messages.push("You can't access that page before logon.");
      res.redirect('/');
    } else {
      next();
    }
}

//Routes
//index page
app.get('/', (req, res) => {
    let messages = [];
    if (req.session.messages) {
        messages = req.session.messages;
        req.session.messages = [];
    }
    res.render('views/index', {messages});
});

app.post(
    '/log-in', passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/', 
        failureMessage: true
    })
);

app.get('/log-out', (req, res) => {
    req.session.destroy(function(err) {
     res.redirect('/');
    })
})

//sign up page
app.get('/sign-up', (req, res) => res.render("sign-up/sign-up-form"));

app.post('/sign-up', async (req, res, next) => {
    try {
        const hashedPassword = await bcryptjs.hash(req.body.password, 10);
        await User.create({ username: req.body.username, password: hashedPassword });
        res.redirect("/");
      } catch (err) {
        return next(err);
      }
});

app.get('/restricted', authMiddleware, (req, res) => {
    if (!req.session.pageCount) {
        req.session.pageCount = 1;
      } else {
        req.session.pageCount++;
      }
      res.render('restricted', {pageCount: req.session.pageCount}); 
})

app.listen(3000, () => console.log('App listening on port 3000...'));

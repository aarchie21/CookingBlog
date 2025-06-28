const User = require('../models/User');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const Recipe = require('../models/Recipe');

exports.getSignup = (req, res) => {
    res.render('signup', { title: 'Sign Up', message: req.flash('error') });
};

exports.postSignup = async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
        req.flash('error', 'Passwords do not match');
        return res.redirect('/signup');
    }
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            req.flash('error', 'Email already registered');
            return res.redirect('/signup');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        req.flash('success', 'Signup successful! Please log in.');
        res.redirect('/login');
    } catch (err) {
        req.flash('error', 'Something went wrong');
        res.redirect('/signup');
    }
};

exports.getLogin = (req, res) => {
    res.render('login', { title: 'Login', message: req.flash('error') });
};

exports.postLogin = (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/profile',
        failureRedirect: '/login',
        failureFlash: true
    })(req, res, next);
};

exports.logout = (req, res) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        req.flash('success', 'You are logged out');
        res.redirect('/login');
    });
};

exports.getProfile = async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    try {
        const userRecipes = await Recipe.find({ email: req.user.email });
        res.render('profile', { title: 'Profile', user: req.user, recipes: userRecipes });
    } catch (err) {
        res.status(500).send('Error loading profile');
    }
}; 
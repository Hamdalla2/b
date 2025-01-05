const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const router = express.Router();


const authenticateToken = (req, res, next) => {
    const token = req.headers["token"];

    if (!token) {
        return res.status(403).json({ message: "Token required" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Invalid token" });
        }

        req.user = user;
        next();
    });
};

router.post('/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = new User({ ...req.body, password: hashedPassword });
        const savedUser = await newUser.save();
        res.status(201).json(savedUser);
    } catch (err) {
        res.status(500).json({ msg: 'Server error', error: err.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) return res.status(400).json({ type: "account", msg: "Account Does Not Exist" });

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) return res.status(400).json({ type: "password", msg: "Wrong password" });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(200).json({ token, user });
    } catch (err) {
        res.status(500).json({ msg: 'Server error', error: err.message });
    }
});

router.get('/users', authenticateToken, async (req, res) => {
    try {
        const users = await User.find();
        if (!user) return res.status(400).json("User not found!");
        res.status(200).json(users);
    } catch (err) {
        res.status(500).json({ msg: 'Server error', error: err.message });
    }
});

router.get('/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ _id: req.user.id });

        if (!user) {
            return res.status(400).json({ msg: 'User not found' });
        }

        res.status(200).json({ user });
    } catch (err) {
        res.status(500).json({ msg: 'Server error', error: err.message });
    }
});

module.exports = router;

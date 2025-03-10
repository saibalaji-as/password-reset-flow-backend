const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');

const router = express.Router();

// Forgot Password
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ message: 'User not found' });

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour expiry
    await user.save();

    const url = process.env.FRONTEND_URL || 'http://localhost:5173'
    const resetLink = `${url}/reset-password/${resetToken}`;
    await sendEmail(email, 'Password Reset', `Click here to reset your password: ${resetLink}`);

    res.json({ message: 'Password reset link sent' });
});

// Reset Password
router.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;

    // Find the user with the matching reset token and ensure it hasn't expired
    const user = await User.findOne({
        resetToken: token,
        resetTokenExpiry: { $gt: Date.now() }  // Check if the token is valid and not expired
    });

    // If no valid user is found, return an error
    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

    // If the token is valid, send the user details to render the reset password form
    res.json({
        message: 'Token is valid. Proceed to reset the password.',
        userId: user._id  // Optionally, send userId to pre-fill forms or other logic
    });
});

// Create a new user
router.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = new User({
            email,
            password: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});

// Login user
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
});

module.exports = router;

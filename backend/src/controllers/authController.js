const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const UserModel = require('../models/User');

const generateToken = (user) =>
    jwt.sign({ id: user.id, username: user.username, email: user.email }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    });

const registerValidation = [
    body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3–30 chars'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must include uppercase, lowercase, and a digit'),
];

const loginValidation = [
    body('identifier').notEmpty().withMessage('Username or email is required'),
    body('password').notEmpty().withMessage('Password is required'),
];

const register = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, email, password } = req.body;
    try {
        if (UserModel.findByEmail(email)) {
            return res.status(409).json({ error: 'Email already registered' });
        }
        if (UserModel.findByUsername(username)) {
            return res.status(409).json({ error: 'Username already taken' });
        }
        const user = UserModel.create({ username, email, password });
        const token = generateToken(user);
        return res.status(201).json({ token, user });
    } catch (err) {
        console.error('Register error:', err);
        return res.status(500).json({ error: 'Registration failed' });
    }
};

const login = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { identifier, password } = req.body;
    try {
        const user = UserModel.findByUsernameOrEmail(identifier);
        if (!user || !UserModel.verifyPassword(password, user.password_hash)) {
            return res.status(401).json({ error: 'Invalid username/email or password' });
        }
        UserModel.updateLastLogin(user.id);
        const token = generateToken(user);
        const { password_hash, ...safeUser } = user;
        return res.json({ token, user: safeUser });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Login failed' });
    }
};

const me = (req, res) => {
    return res.json({ user: req.user });
};

module.exports = { register, login, me, registerValidation, loginValidation };

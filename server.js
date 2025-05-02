const express = require('express');
const path = require('path');
const redis = require('ioredis');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const mongoose = require('mongoose');
const argon2 = require('argon2');

const redb = new redis({ path: '/var/run/redis/redis.sock' });

const { create_ecdh, random_uuid } = require('crypto');

require('dotenv').config();
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const PORT = process.env.PORT || 4000;

//mongodb
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('MongoDB connected successfully');
        app.listen(PORT, () => {
          console.log(`API server listening on http://127.0.0.1:${PORT}`);
        });
    })
    .catch(err => {
        console.log('MongoDB connection error:', err);
        process.exit(1);
    });

const user_schema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    verified: { type: Boolean, default: false },
    verification_token: { type: String },
    reset_token: { type: String },
    reset_expiry: { type: Date },
});

const user = mongoose.model('user', user_schema);

app.post('/a/register', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email)
        return res.status(400).json({ success: false, message: 'Username, password and email required' });

    const existing_user = await user.findOne({ username });
    if (existing_user)
        return res.status(400).json({ success: false, message: 'Username is already taken' });

    try
    {
        const hashed_password = await argon2.hash(password);

        const verification_token = crypto.randomBytes(20).toString('hex');

        const new_user = new user({
            username,
            password: hashed_password,
            email,
            verification_token
        });

        await new_user.save();

        await send_email_verification(email, verification_token);

        res.status(201).json({ success: true });
    }
    catch (err)
    {
        console.error('Error during registration:', err);
        res.status(500).json({ success: false, message: 'Failed to register user' });
    }
});

app.post('/a/login', async (req, res) => {
    const { username, password, client_pub } = req.body;

    if (!username || !password)
        return res.status(400).json({ success: false, message: 'Username and password are required' });

    if (!client_pub)
        return res.status(400).json({ success: false, message: 'Client public key not provided' });

    try {
        const found_user = await user.findOne({ username });
        if (!found_user)
            return res.status(400).json({ success: false, message: 'Invalid username or password' });

        if (!found_user.verified)
            return res.status(400).json({ success: false, message: 'User must verify email address before attempting login' });

        const is_password_valid = await argon2.verify(found_user.password, password);
        if (!is_password_valid)
            return res.status(400).json({ success: false, message: 'Invalid username or password' });

        const ecdh = createECDH('secp256k1');
        const server_pub = ecdh.generateKeys('hex');
        const shared_secret = ecdh.computeSecret(Buffer.from(client_pub, 'hex')).toString('hex');

        const session_id = randomUUID();
        await redis.multi()
            .set(`session:${session_id}`, shared_secret, 'EX', 24 * 60 * 60)
            .sadd(`user_sessions:${found_user._id}`, session_id)
            .expire(`user_sessions:${found_user._id}`, 24 * 60 * 60)
            .exec();

        res.status(200).json({
            success: true,
            message: 'Login successful',
            server_pub: server_pub,
            session_id
        });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ success: false, message: 'Failed to login' });
    }
});

//emailing
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

function generate_verification_token() {
    return crypto.randomBytes(20).toString('hex');
}

async function send_email_verification(email, token) {
    const link = `https://learn.ben256.com/a/verify-email?token=${token}`;
    const mail_options = {
        from: '"ben256" <noreply@ben256.com>',
        to: email,
        subject: 'Verify your email for ben256',
        text: `Verify your email address with the following link:\n\n${link}`,
        html: `<h1>Verify your email for ben256</h1><p>Verify your email address with the following link:</p><a href="${link}">Verify your Email</a>`,
    };

    try {
        await transporter.sendMail(mail_options);
        console.log(`Verification email sent to ${email}`);

        return { success: true, message: 'Verification email sent' };
    } catch (error) {
        console.error('Error sending email:', error);
        return { success: false, message: 'Failed to send verification email' };
    }
}

async function send_password_reset(email, token) {
    const link = `https://learn.ben256.com/reset-password?token=${token}`;
    const mail_options = {
        from: '"ben256" <noreply@ben256.com>',
        to: email,
        subject: 'Password reset for ben256',
        text: `Reset your password with the following link:\n\n${link}`,
        html: `<h1>Password reset for ben256</h1><p>Reset your password with the following link:</p><a href="${link}">Reset your Password</a>`,
    };

    try {
        await transporter.sendMail(mail_options);
        console.log(`Password reset email sent to ${email}`);

        return { success: true, message: 'Password reset email sent' };
    } catch (error) {
        console.error('Error sending email:', error);
        return { success: false, message: 'Failed to send reset email' };
    }
}

app.get('/a/verify-email', async (req, res) => {
    const { token } = req.query;
    if (!token)
        return res.status(400).send('Verification token missing');

    const found_user = await user.findOne({ verification_token: token });
    if (!found_user)
        return res.status(400).send('Invalid or expired token');

    found_user.verified = true;
    found_user.verification_token = undefined;
    await found_user.save();

    res.send('Successfully verified email');
});

app.post('/a/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email)
        return res.status(400).json({ success: false, message: 'Email required' });

    const found_user = await user.findOne({ email });
    if (!found_user)
        return res.json({ success: true });

    const reset_token = crypto.randomBytes(20).toString('hex');
    found_user.reset_token = reset_token;
    found_user.reset_expiry = Date.now() + 3600_000;

    await found_user.save();

    await send_password_reset(email, reset_token);

    res.json({ success: true });
});

app.post('/a/reset-password', async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password)
        return res.status(400).json({ success: false, message: 'Token and new password required' });

    const found_user = await user.findOne({
        reset_token: token,
        reset_expiry: { $gt: Date.now() }
    });
    if (!found_user)
        return res.status(400).json({ success: false, message: 'Invalid or expired token' });

    found_user.password = await argon2.hash(password);
    found_user.reset_token = undefined;
    found_user.reset_expiry = undefined;
    await found_user.save();

    res.json({ success: true });
});

//redis

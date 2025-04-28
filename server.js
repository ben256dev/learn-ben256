const express = require('express');
const path = require('path');
const Redis = require('ioredis');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const mongoose = require('mongoose');
const argon2 = require('argon2');

require('dotenv').config();

const app = express();
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
    email: { type: String, required: true }
});

const user = mongoose.model('user', user_schema);

app.post('/a/register', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ success: false, message: 'Username, password and email required' });
    }

    const existing_user = await user.findOne({ username });
    if (existing_user) {
        return res.status(400).json({ success: false, message: 'Username is already taken' });
    }

    try {
        const hashed_password = await argon2.hash(password);

        const new_user = new user({
            username,
            password: hashed_password,
            email
        });

        await new_user.save();
        res.status(201).json({ success: true, message: 'User registered successfully' });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ success: false, message: 'Failed to register user' });
    }
});

app.post('/a/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    try {
        const found_user = await user.findOne({ username });
        if (!found_user) {
            return res.status(400).json({ success: false, message: 'Invalid username or password' });
        }

        const is_password_valid = await argon2.verify(found_user.password, password);
        if (!is_password_valid) {
            return res.status(400).json({ success: false, message: 'Invalid username or password' });
        }

        res.status(200).json({ success: true, message: 'Login successful' });
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

async function send_email_verification(user_email) {
    const verification_token = generate_verification_token();
    const verification_link = `https://learn.ben256.com/a/verify-email?token=${verification_token}`;
    const mail_options = {
        from: '"ben256" <noreply@ben256.com>',
        to: user_email,
        subject: 'Verify your email for ben256',
        text: `Verify your email address with the following link:\n\n${verification_link}`,
        html: `<h1>Verify your email for ben256</h1><p>Verify your email address with the following link:</p><a href="${verification_link}">Verify your Email</a>`,
    };

    try {
        await transporter.sendMail(mail_options);
        console.log(`Verification email sent to ${user_email}`);

        return { success: true, message: 'Verification email sent' };
    } catch (error) {
        console.error('Error sending email:', error);
        return { success: false, message: 'Failed to send verification email' };
    }
}

/*
send_email_verification('benjaminblodgett311@u.boisestate.edu').then(response => {
    console.log(response.message);
});
*/

//redis
const redis = new Redis({ path: '/var/run/redis/redis.sock' });

/*
app.get('/verify-email', (req, res) => {
    const { token } = req.query;

    try {

    }
}
*/

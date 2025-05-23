const express = require('express');
const path = require('path');
const redis = require('ioredis');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const mongoose = require('mongoose');
const argon2 = require('argon2');
const cookieparser = require('cookie-parser');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const redb = new redis({ path: '/var/run/redis/redis.sock' });

const { createECDH, randomUUID } = require('crypto');

require('dotenv').config();
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieparser());

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
    mfa_secret: { type: String },
});

const user = mongoose.model('user', user_schema);

app.post('/a/register', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email)
        return res.status(400).json({ success: false, message: 'Username, password and email required' });

    if (await user.findOne({ username }))
        return res.status(400).json({ success: false, message: 'Username is already taken' });

    if (await user.findOne({ email }))
        return res.status(400).json({ success: false, message: 'Email already registered' });

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
    const { username, password, client_pub, otp } = req.body;

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

        //session info
        const incoming_device = req.headers['x-device-id'];
        const device_key = `user_devices:${found_user._id}`;
        const device_id = incoming_device || randomUUID();
        const raw = await redb.hget(device_key, device_id) || '[]';
        const sessions = JSON.parse(raw);
        const session_id = randomUUID();
        const total_devices  = await redb.hlen(device_key);
        const is_new_device  = !incoming_device || sessions.length === 0;

        //otp
        if (total_devices > 0 && is_new_device) {
            if (!otp) {
                return res.status(400).json({ success: false, message: 'MFA code required for new device' });
            }
            const otp_is_valid = speakeasy.totp.verify({
                secret:   found_user.mfa_secret,
                encoding: 'base32',
                token:    otp,
                window:   1
            });
            if (!otp_is_valid) {
                return res.status(400).json({ success: false, message: 'Invalid MFA code' });
            }
        }

        //ecdh
        const ecdh = createECDH('prime256v1');
        const server_pub = ecdh.generateKeys('hex', 'uncompressed');
        const shared_secret = ecdh.computeSecret(Buffer.from(client_pub, 'hex')).toString('hex');

        sessions.push(session_id);

        await redb.multi()
            .set(`session:${session_id}`, shared_secret, 'EX', 24 * 60 * 60)
            .set(`session_user:${session_id}`, found_user._id.toString(), 'EX', 24 * 60 * 60)
            .hset(device_key, device_id, JSON.stringify(sessions))
            .expire(device_key, 24 * 60 * 60)
            .exec();

        res.json({
            success: true,
            server_pub,
            user: { username: found_user.username },
            device_id,
            session_id,
            sessions
        });

    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ success: false, message: 'Failed to login' });
    }
});

app.get('/a/status', async (req, res) => {
    const { session_id, device_id } = req.cookies;
    if (!session_id)
        return res.json({ loggedIn: false });

    const [ userId, secret ] = await Promise.all([
        redb.get(`session_user:${session_id}`),
        redb.get(`session:${session_id}`)
    ]);

    if (!userId || !secret)
        return res.json({ loggedIn: false });

    const raw = await redb.hget(`user_devices:${userId}`, device_id) || '[]';
    const sessions = JSON.parse(raw);
    if (sessions.length === 0)
        return res.json({ loggedIn: false });

    const u = await user.findById(userId, 'username');

    return res.json({
        loggedIn: true,
        username: u.username,
        sessions
    });
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

async function require_auth(req, res, next) {
    const session_id = req.headers['x-session-id'];
    const timestamp  = req.headers['x-timestamp'];
    const signature  = req.headers['x-signature'];
    if (!session_id || !timestamp || !signature) {
        return res.status(401).json({ success: false, message: 'Missing authentication headers' });
    }

    const secret = await redb.get(`session:${session_id}`);
    if (!secret) {
        return res.status(401).json({ success: false, message: 'Invalid session' });
    }

    const payload = `${timestamp}|${req.method}|${req.originalUrl}|${session_id}`;

    const expected = crypto.createHmac('sha256', secret)
                           .update(payload)
                           .digest('hex');

    const sig_buff = Buffer.from(signature, 'hex');
    const exp_buff = Buffer.from(expected,  'hex');
    if (sig_buff.length !== exp_buff.length ||
        !crypto.timingSafeEqual(sig_buff, exp_buff)) {
        return res.status(403).json({ success: false, message: 'Invalid signature' });
    }

    const user_id = await redb.get(`session_user:${session_id}`);
    if (!user_id) {
        return res.status(401).json({ success: false, message: 'Session has no user' });
    }
    req.user_id = user_id;

    next();
}

app.delete('/a/revoke-session/:session_id', require_auth, async (req, res) => {
    const revoke_session_id = req.params.session_id;
    if (!revoke_session_id)
        return res.status(400).json({ success: false, message: 'session_id is required' });

    const user_id = req.user_id;
    const device_id = req.device_id;
    const raw_sessions = await redb.hget(`user_devices:${user_id}`, device_id) || '[]';
    const sessions = JSON.parse(raw_sessions);

    if (sessions.length <= 1)
        return res.status(400).json({ success: false, message: 'Cannot revoke device\'s sole session' });

    if (!sessions.includes(revoke_session_id))
        return res.status(403).json({ success: false, message: 'Session not found on this device' });

    const updated_sessions = sessions.filter(s => s !== revoke_session_id);
    await redb.multi()
        .del(`session:${revoke_session_id}`)
        .del(`session_user:${revoke_session_id}`)
        .hset(`user_devices:${user_id}`, device_id, JSON.stringify(updated_sessions))
        .exec();

    res.json({ success: true, sessions: updated_sessions });
});

app.delete('/a/revoke-device/:device_id', require_auth, async (req, res) => {
    const target_device_id = req.params.device_id;
    if (!target_device_id)
        return res.status(400).json({ success: false, message: 'device_id is required' });

    const user_id = req.user_id;

    const all_devices = await redb.hgetall(`user_devices:${user_id}`);
    if (!Object.prototype.hasOwnProperty.call(all_devices, target_device_id))
        return res.status(404).json({ success: false, message: 'Device not found' });

    const raw_sessions = all_devices[target_device_id] || '[]';
    const sessions_to_kill = JSON.parse(raw_sessions);
    const multi = redb.multi();

    sessions_to_kill.forEach(sid => {
        multi.del(`session:${sid}`);
        multi.del(`session_user:${sid}`);
    });
    multi.hdel(`user_devices:${user_id}`, target_device_id);
    await multi.exec();

    res.json({ success: true, device_id: target_device_id });
});

// MFA enable
app.post('/a/enable-mfa', require_auth, async (req, res) => {
    const found_user = await user.findById(req.user_id);
    if (!found_user)
        return res.status(404).json({ success: false, message: 'User not found' });

    if (found_user.mfa_secret)
        return res.status(400).json({ success: false, message: 'MFA already enabled' });

    const secret = speakeasy.generateSecret({
        name: `YourApp (${found_user.username})`
    });

    await user.updateOne(
        { _id: found_user._id },
        { mfa_secret: secret.base32 }
    );

    qrcode.toDataURL(secret.otpauth_url, (err, uri) => {
        if (err)
            return res.status(500).send('Error generating QR');
        res.json({ qr: uri });
    });
});

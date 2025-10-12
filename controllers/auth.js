const User = require('../model/user');
const httpStatusText = require('../utils/httpStatusText');
const userRole = require('../utils/userRole');
const config = require('../config/index');
const generateRandomToken = require('../utils/createToken');
const sendEmail = require('../utils/sendEmail');

const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const register = async (req, res, next) => {
    const { firstName, lastName, email, password } = req.body;
    try{
        const oldUser = await User.findOne({ email });
        if(oldUser){
            const error = new Error('E-mail exists already')
            error.statusCode = 422;
            error.status = httpStatusText.FAIL;
            error.data = 'E-mail exists already, please pick a different one.';
            throw error;
        }
        const hashPassword = await bcrypt.hash(password, 12);

        const user = new User({
            firstName: firstName,
            lastName: lastName,
            email: email,
            password: hashPassword,
            userRole: userRole.USER,
            avatar: req.file ? req.file.filename : null,
            emailVerified: false
        })
        
        const emailVerificationToken = generateRandomToken();
        user.emailVerificationToken = emailVerificationToken
        user.emailVerificationExpires = Date.now() + 1 * 60 * 60 * 1000;
        
        await user.save();

        const verifyURL = `${config.clientUrl}/verify-email/${emailVerificationToken}`;
        const html = `
            <p>Hello ${user.firstName},</p>
            <p>Click the link below to verify your email address:</p>
            <a href="${verifyURL}">${verifyURL}</a>
            <p>This link will expire in 1 hours.</p>
        `;

        await sendEmail(user.email, 'Verify your email', html, false);

        res.status(201).json({ status: httpStatusText.SUCCESS, message: 'User registered successfully, please check your email to verify your account' });

    } catch (error) {
        if (req.file) {
        const filePath = path.join(__dirname, '..', 'uploads', req.file.filename);
        fs.unlink(filePath, (err) => { /* ignore */ });
        }
        next(error);
    }
}

const verifyEmail = async (req, res, next) => {
    const token = req.params.token;
    try{
        if(!token){
            const error = new Error('Invalid verification link.');
            error.statusCode = 400;
            error.status = httpStatusText.FAIL;
            error.data = '';
            throw error;
        }
        const user = await User.findOne({
            emailVerificationToken: token,
            emailVerificationExpires: { $gt: Date.now() }
        });
        if(!user){
            return res.status(400).json({ status: httpStatusText.FAIL, message: 'Invalid or expired verifiction link, Please request verification again.' });
        }

        user.emailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;

        const accessToken = jwt.sign({ id: user._id, email: user.email, userRole: user.userRole }, config.jwtSecret.key, { expiresIn : config.jwtSecret.expiresIn });
        const refreshToken = jwt.sign({ id: user._id }, config.jwtRefresh.key, { expiresIn: config.jwtRefresh.expiresIn });
        
        user.sessions.push({
            refreshToken,
            deviceInfo: req.headers['user-agent'] || "Unknown device",
            expiresAt: new Date(Date.now() + 30*24*60*60*1000)
        });
        await user.save();

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            // secure: true,
            sameSite: "none",
            maxAge: 15 * 60 * 1000,
        })
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            // secure: true,
            sameSite: "none",
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });
        res.status(201).json({ status: httpStatusText.SUCCESS, message: 'Account created and verified successfully.', data: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.userRole,
            avatar: user.avatar,
            createdAt: user.createdAt,
        }});

    } catch (error) {
        next(error);
    }
}

const resendVerification = async (req, res, next) => {
    const email = req.body.email;
    try {
        const user = await User.findOne({ email: email });
        if(!user) {
            const error = new Error('If an account exists, a verification link has been sent.')
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            throw error;
        }
        if(user.emailVerified) {
            return res.status(200).json({ status: httpStatusText.SUCCESS, message: 'Email is already verified.' });
        }

        const emailVerificationToken = generateRandomToken();
        user.emailVerificationToken = emailVerificationToken
        user.emailVerificationExpires = Date.now() + 1 * 60 * 60 * 1000;
        
        await user.save();

        const verifyURL = `${config.clientUrl}/verify-email/${emailVerificationToken}`;
        const html = `Click to verify: <a href="${verifyURL}">${verifyURL}</a>`;
        await sendEmail(user.email, 'Verify your email', html, false);

        return res.status(200).json({ status: httpStatusText.SUCCESS, message: 'If an account exists, a verification link has been sent.' });

    } catch (error) {
        next(error);
    }
}

const login = async (req, res, next) => {
    const { email, password } = req.body;
    try{
        const user = await User.findOne({ email }).select("+password");
        if(!user) {
            const error = new Error('A user with this email could not be found.')
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            error.data = 'User not found';
            throw error;
        }
        const isEqual = await bcrypt.compare(password, user.password);
        if(!isEqual) {
            const error = new Error('Incorrect password.');
            error.statusCode = 401;
            error.status = httpStatusText.FAIL;
            error.data = 'Incorrect password, please try again.';
            throw error;
        }

        const OTP = Math.floor(100000 + Math.random() * 900000).toString();
        user.otpCode = OTP;
        user.otpExpires = Date.now() + 1 * 60 * 1000;
        user.save();

        const html = `<p>Hello ${user.firstName},</p>
            <p>Your login code is: <b>${OTP}</b></p>
            <p>This code will expire in 5 minutes.</p>`;
        await sendEmail(user.email, "Your Login Code", html);

        res.status(200).json({ status: httpStatusText.SUCCESS, message: 'OTP send too your email, Please verify to complete login.' });

    }catch (error) {
        next(error);
    }
}

const verifyOTP = async (req, res, next) => {
    const { email, OTP, rememberMe } = req.body;
    try {
        const user = await User.findOne({ email: email });
        if(!user || !user.otpCode) {
            const error = new Error('No OTP request found.')
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            throw error;
        }
        if(user.otpCode != OTP || user.otpExpires < Date.now() ) {
            const error = new Error('Invalid or expired OTP.');
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            throw error;
        }

        user.otpCode = null;
        user.otpExpires = null;
        const refreshExpiry = rememberMe ? config.jwtRefresh.expiresInRM : config.jwtRefresh.expiresIn;

        const accessToken  = jwt.sign({ id: user._id, email: user.email, userRole: user.userRole }, config.jwtSecret.key, { expiresIn: config.jwtSecret.expiresIn });
        const refreshToken = jwt.sign({ id: user._id }, config.jwtRefresh.key, { expiresIn: refreshExpiry });

        user.sessions.push({
            refreshToken,
            deviceInfo: req.headers['user-agent'] || "Unknown device",
            expiresAt: new Date(Date.now() + (rememberMe ? config.jwtRefresh.expiresInRM : config.jwtRefresh.expiresIn) * 24 * 60 * 60 * 1000)
        });
        await user.save();
        
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            // secure: true,
            sameSite: "none",
            maxAge: 15 * 60 * 1000,
        })
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            // secure: true,
            sameSite: "none",
            maxAge: (rememberMe ? config.jwtRefresh.expiresInRM : config.jwtRefresh.expiresIn) * 24 * 60 * 60 * 1000,
        });
        res.status(200).json({ status: httpStatusText.SUCCESS, data: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.userRole,
            avatar: user.avatar,
            createdAt: user.createdAt,
        }});
        
    } catch (error) {
        next(error);
    }
}

const forgetPassword = async (req, res, next) => {
    const email = req.body.email;
    try{
        const user = await User.findOne({ email });
        if(!user) {
            const error = new Error('Invalid email address');
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            error.data = 'A user with this email could not be found, Please check the validity of your email address.';
            throw error;
        }
        user.resetToken = generateRandomToken();
        user.resetTokenExpiration = Date.now() + 900000;
        
        await user.save();
        
        const resetURL = `${config.clientUrl}/reset-password/${user.resetToken}`;
        await sendEmail(user.email, "Reset Password", `Click the following link to reset your password: ${resetURL}`);

        res.status(200).json({ status: httpStatusText.SUCCESS, message: 'Reset link sent to your email.' });

    } catch (error) {
        next(error);
    }
}

const resetPassword = async (req, res, next) => {
    const token = req.params.token;
    const newPassword = req.body.password;

    try{
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() }
        });

        if(!user) {
            const error = new Error('Invalid or expired password reset token.');
            error.statusCode = 400;
            error.status = httpStatusText.FAIL;
            error.data = {
                reason: 'The provided reset token is invalid or has expired.',
                hint: 'Please request a new password reset link.'
            };
            throw error;
        }
        const isMatch = await bcrypt.compare( newPassword, user.password );
        if(isMatch) {
            const error = new Error('Invalid password');
            error.statusCode = 400;
            error.status = httpStatusText.FAIL;
            error.data = 'The old password cannot be entered, Please enter a new password.';
            throw error;
        }

        const hashNewPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashNewPassword;

        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        user.sessions = [];
        
        await user.save();
        res.status(200).json({ status: httpStatusText.SUCCESS, message: 'Password has been reset successfully.' });

    } catch (error) {
        next(error);
    }
}

const logout = async (req, res, next) => {
    const userId = req.user.id ;
    try{
        const user = await User.findById(userId);
        if(!user) {
            const error = new Error('User not found !');
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            error.data = 'You cannot log out from a non-existent email address.';
            throw error;
        }
        const refreshToken = req.cookies.refreshToken;
        user.sessions = user.sessions.filter(
            session => session.refreshToken !== refreshToken
        );
        await user.save();
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        res.status(200).json({ status: httpStatusText.SUCCESS, message: 'Logged out successfully.' });

    } catch (error) {
        next(error);
    }
}

module.exports = {
    register,
    verifyEmail,
    resendVerification, 
    login,
    verifyOTP,
    forgetPassword,
    resetPassword,
    logout
}
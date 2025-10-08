const User = require('../model/user');
const httpStatusText = require('../utils/httpStatusText');
const userRole = require('../utils/userRole');
const config = require('../config/index');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require("crypto");
const fs = require('fs');
const path = require('path');

const register = async (req, res, next) => {
    const { firstName, lastName, email, password, role } = req.body;
    try{
        const oldUser = await User.findOne({ email });
        if(oldUser){
            const error = new Error('E-mail exists already, please pick a different one.')
            error.statusCode = 422;
            error.status = httpStatusText.FAIL;
            error.data = 'E-mail exists already';
            throw error;
        }
        const hashPassword = await bcrypt.hash(password, 12);

        const user = new User({
            firstName: firstName,
            lastName: lastName,
            email: email,
            password: hashPassword,
            userRole: role || userRole.USER,
            avatar: req.file ? req.file.filename : null
        })

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
            sameSite: "lax",
            maxAge: 15 * 60 * 1000,
        })
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            // secure: true,
            sameSite: "lax",
            maxAge: 30 * 24 * 60 * 60 * 1000,
        });
        res.status(201).json({ status: httpStatusText.SUCCESS, data: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.userRole,
            avatar: user.avatar,
            createdAt: user.createdAt,
        }});

    } catch (error) {
        if (req.file) {
        const filePath = path.join(__dirname, '..', 'uploads', req.file.filename);
        fs.unlink(filePath, (err) => { /* ignore */ });
        }
        next(error);
    }
}

const login = async (req, res, next) => {
    const { email, password } = req.body;
    try{
        const user = await User.findOne({ email });
        if(!user) {
            const error = new Error('A user with this email could not be found.')
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            throw error;
        }
        const isEqual = await bcrypt.compare(password, user.password);
        if(!isEqual) {
            const error = new Error('Incorrect password.');
            error.statusCode = 401;
            error.status = httpStatusText.FAIL;
            throw error;
        }

        const accessToken  = jwt.sign({ id: user._id, email: user.email, userRole: user.userRole }, config.jwtSecret.key, { expiresIn: config.jwtSecret.expiresIn });
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
            sameSite: "lax",
            maxAge: 15 * 60 * 1000,
        })
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            // secure: true,
            sameSite: "lax",
            maxAge: 30 * 24 * 60 * 60 * 1000,
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

    }catch (error) {
        next(error);
    }
}

const forgetPassword = async (req, res, next) => {
    const email = req.body.email;
    try{
        const user = await User.findOne({ email });
        if(!user) {
            const error = new Error('A user with this email could not be found, Please check the validity of your email address.')
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            throw error;
        }
        user.resetToken = crypto.randomBytes(32).toString('hex');
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
            const error = new Error('Invalid or expired reset token.');
            error.statusCode = 400;
            error.status = httpStatusText.FAIL;
            throw error;
        }
        const isMatch = await bcrypt.compare( newPassword, user.password );
        if(isMatch) {
            return res.status(400).json({ status: httpStatusText.FAIL, message: "The old password cannot be entered, Please enter a new password." });
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
    login,
    forgetPassword,
    resetPassword,
    logout
}
const express = require('express');

const authController = require('../controllers/auth');
const upload = require('../middlewares/upload');
const validate = require('../middlewares/auth/validate-auth.js');
const handleValidationErrors = require('../middlewares/auth/handleValidationErrors.js');
const verifyToken = require('../middlewares/auth/verifyToken.js');
const authLimiter = require('../middlewares/auth/rateLimiter.js');

const router = express.Router();

router.post('/register',authLimiter, upload.single('avatar'), validate.register, handleValidationErrors, authController.register);

router.post('/login', authLimiter, validate.login, handleValidationErrors, authController.login);

router.post('/forget-password', authLimiter, authController.forgetPassword);

router.post('/reset-password/:token', authLimiter, authController.resetPassword);

router.post('/logout', verifyToken, authController.logout);

module.exports = router;
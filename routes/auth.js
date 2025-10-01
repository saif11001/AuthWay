const express = require('express');

const controllerAuth = require('../controllers/auth');
const upload = require('../middlewares/upload');
const validate = require('../middlewares/validate-auth');
const handleValidationErrors = require('../middlewares/handleValidationErrors');
const verifyToken = require('../middlewares/verifyToken.js');
const authLimiter = require('../middlewares/rateLimiter');

const router = express.Router();

router.post('/register',authLimiter, upload.single('avatar'), validate.register, handleValidationErrors, controllerAuth.register);

router.post('/login', authLimiter, validate.login, handleValidationErrors, controllerAuth.login);

router.post('/forget-password', authLimiter, controllerAuth.forgetPassword);

router.post('/reset-password/:token', authLimiter, controllerAuth.resetPassword);

router.post('/logout', verifyToken, controllerAuth.logout);

module.exports = router;
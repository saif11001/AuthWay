const express = require('express');

const controllerUser = require('../controllers/user');
const verifyToken = require('../middlewares/auth/verifyToken');
const allowedTo = require('../middlewares/auth/allowedTo');
const userRole = require('../utils/userRole');
const validate = require('../middlewares/auth/validate-auth');
const handleValidationErrors = require('../middlewares/auth/handleValidationErrors');
const authLimiter = require('../middlewares/auth/rateLimiter');
const upload = require('../middlewares/upload');

const router = express.Router();

router.get('/all', verifyToken, allowedTo(userRole.ADMIN), controllerUser.getAllUsers);

router.get('/me', verifyToken, controllerUser.getUser);

router.put('/update', authLimiter, verifyToken, upload.single('avatar'), validate.updateUser, handleValidationErrors, controllerUser.updateUser);

router.delete('/delete', verifyToken, controllerUser.deleteUser);

module.exports = router;
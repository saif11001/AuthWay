const express = require('express');

const controllerUser = require('../controllers/user');
const verifyToken = require('../middlewares/verifyToken');
const allowedTo = require('../middlewares/allowedTo');
const userRole = require('../utils/userRole');
const validate = require('../middlewares/validate-auth');
const handleValidationErrors = require('../middlewares/handleValidationErrors');
const authLimiter = require('../middlewares/rateLimiter');
const upload = require('../middlewares/upload');

const router = express.Router();

router.get('/all', verifyToken, allowedTo(userRole.ADMIN), controllerUser.getAllUsers);

router.get('/me', verifyToken, controllerUser.getUser);

router.put('/update', authLimiter, verifyToken, upload.single('avatar'), validate.updateUser, handleValidationErrors, controllerUser.updateUser);

router.delete('/delete', verifyToken, controllerUser.deleteUser);

module.exports = router;
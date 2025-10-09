const express = require('express');

const userController = require('../controllers/user');
const verifyToken = require('../middlewares/auth/verifyToken');
const allowedTo = require('../middlewares/auth/allowedTo');
const userRole = require('../utils/userRole');
const validate = require('../middlewares/auth/validate-auth');
const handleValidationErrors = require('../middlewares/auth/handleValidationErrors');
const authLimiter = require('../middlewares/auth/rateLimiter');
const upload = require('../middlewares/upload');

const router = express.Router();

router.get('/all', verifyToken, allowedTo(userRole.ADMIN), userController.getAllUsers);

router.get('/me', verifyToken, userController.getUser);

router.put('/update', authLimiter, verifyToken, upload.single('avatar'), validate.updateUser, handleValidationErrors, userController.updateUser);

router.patch("/role/:id", verifyToken, allowedTo(userRole.ADMIN), userController.updateUserRole);

router.delete('/delete', verifyToken, userController.deleteUser);

module.exports = router;
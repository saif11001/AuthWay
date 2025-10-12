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

/**
 * @swagger
 * tags:
 *   name: Users
 *   description: User management routes
 */

/**
 * @swagger
 * /api/user/all:
 *   get:
 *     summary: Get all users (Admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all users
 *       403:
 *         description: Forbidden
 */
router.get('/all', verifyToken, allowedTo(userRole.ADMIN), userController.getAllUsers);

/**
 * @swagger
 * /api/user/me:
 *   get:
 *     summary: Get current logged-in user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Unauthorized
 */
router.get('/me', verifyToken, userController.getUser);

/**
 * @swagger
 * /api/user/update:
 *   put:
 *     summary: Update current user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               avatar:
 *                 type: string
 *                 format: binary
 *               name:
 *                 type: string
 *                 example: Saif Eldeen
 *               email:
 *                 type: string
 *                 example: newemail@example.com
 *     responses:
 *       200:
 *         description: User updated successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.put('/update', authLimiter, verifyToken, upload.single('avatar'), validate.updateUser, handleValidationErrors, userController.updateUser);

/**
 * @swagger
 * /api/user/role/{id}:
 *   patch:
 *     summary: Update user role (Admin only)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - role
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [user, admin, manager]
 *                 example: admin
 *     responses:
 *       200:
 *         description: User role updated successfully
 *       403:
 *         description: Forbidden
 *       404:
 *         description: User not found
 */
router.patch("/role/:id", verifyToken, allowedTo(userRole.ADMIN), userController.updateUserRole);

/**
 * @swagger
 * /api/user/delete:
 *   delete:
 *     summary: Delete current user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       401:
 *         description: Unauthorized
 */
router.delete('/delete', verifyToken, userController.deleteUser);

module.exports = router;
const { body } = require('express-validator');
const User = require('../../model/user');

const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/;

const register = [
    body('firstName')
        .notEmpty().withMessage('Your first name is required !')
        .isLength({ min: 2, max: 15 }).withMessage('Your name must be between 2 and 15 characters')
        .trim()
        .bail(),
    body('lastName')
        .notEmpty().withMessage('Your last name is required !')
        .isLength({ min: 2, max: 15}).withMessage('Your name must be between 2 and 15 characters')
        .bail(),
    body('email')
        .trim()
        .isEmail().withMessage('Please enter a valid email.')
        .toLowerCase()
        .normalizeEmail()
        .custom(async (value) => {
            const userDOC = await User.findOne({email: value})
                if(userDOC) {
                    throw new Error('E-mail exists already, please pick a different one.')
                }
        })
        .bail(),
    body('password')
        .trim()
        .matches(passwordRegex).withMessage('Password must be 8-20 characters, include uppercase, lowercase, number, and special character.')
        .isLength({ min: 8, max: 20 }).withMessage('Your password must be between 8 and 20 characters long.')
        .bail(),
    body('role')
        .optional()
        .trim()
        .bail()
]

const resendVerification = [
    body('email')
        .notEmpty().withMessage('The E-mail part must be filled in !')
        .isEmail().withMessage('Please enter a valid email.')
        .normalizeEmail()
        .toLowerCase()
        .trim()
        .bail(),
]

const login = [
    body('email')
        .notEmpty().withMessage('Your E-mail is required !')
        .isEmail().withMessage('Please enter a valid email.')
        .normalizeEmail()
        .toLowerCase()
        .trim()
        .bail(),
    body('password')
        .isLength({ min: 8, max: 20}).withMessage('Your password must be between 6 and 20 characters long.')
        .trim()
        .bail()
]

const verifyOTP = [
    body('email')
        .notEmpty().withMessage('Your E-mail is required !')
        .isEmail().withMessage('Please enter a valid email.')
        .normalizeEmail()
        .toLowerCase()
        .trim()
        .bail(),
    body('OTP')
        .notEmpty().withMessage("OTP is required!")
        .isLength({ min: 6, max: 6 }).withMessage("OTP must be 6 digits.")
        .isNumeric().withMessage("OTP must contain only numbers.")
        .trim()
        .bail(),
]

const updateUser = [
    body('firstName')
        .optional()
        .isLength({ min: 2, max: 15 }).withMessage('Your name must be between 2 and 15 characters')
        .trim()
        .bail(),
    body('lastName')
        .optional()
        .isLength({ min: 2, max: 15}).withMessage('Your name must be between 2 and 15 characters')
        .trim()
        .bail(),
    body('email')
        .optional()
        .trim()
        .isEmail().withMessage('Please enter a valid email.')
        .toLowerCase()
        .normalizeEmail()
        .custom(async (value, { req }) => {
            const userDOC = await User.findOne({ email: value });
            if (userDOC && userDOC._id.toString() !== req.user.id.toString()) {
                throw new Error('E-mail exists already, please pick a different one.');
            }
        })
        .bail(),
    body('password')
        .optional()    
        .trim()
        .bail()
        .matches(passwordRegex).withMessage('Password must be 8-20 characters, include uppercase, lowercase, number, and special character.')
        .isLength({ min: 8, max: 20 }).withMessage('Your password must be between 6 and 20 characters long.'),
]

module.exports = {
    register,
    resendVerification,
    login,
    verifyOTP,
    updateUser
}
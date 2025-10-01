const mongoose = require('mongoose');
const userRole = require('../utils/userRole');

const Schema = mongoose.Schema;

const userSchema = new Schema (
    {
        firstName: {
            type: String,
            required: [ true, "First name is required"],
            trim: true,
            minlength: [ 2, "First name must be at least 2 characters long" ],
            maxlength: [ 15, "First name must be less than 15 characters" ]
        },
        lastName: {
            type: String,
            required: [ true, "Last name is required" ],
            trim: true,
            minlength: [ 2, "Last name must be at least 2 characters long" ],
            maxlength: [ 15, "Last name must be less than 15 characters" ]
        },
        email: {
            type: String,
            required: [ true, "Email is required" ],
            unique: true,
            lowercase: true,
            trim: true,
            match: [ /^\S+@\S+\.\S+$/, "Please provide a valid email address" ]
        },
        password: {
            type: String,
            required: [ true, "Password is required" ],
            minlength: [ 8, "Password must be at least 8 characters long" ],
            maxlength: [ 20, "Password must be less than 20 characters" ]
        },
        userRole: {
            type: String,
            enum: [userRole.ADMIN, userRole.USER],
            default : userRole.USER,
            required: true
        },
        avatar: {
            type: String,
            default: null
        },
        sessions: [
            {
                refreshToken: String,
                deviceInfo: String,
                createdAt: { type: Date, default: Date.now },
                expiresAt: Date
            },
            {
                _id: false
            }
        ],
        resetToken: {
            type: String,
            default: null
        },
        resetTokenExpiration: {
            type: Date,
            default: null
        }
    },
    {
        timestamps: true
    }
)

module.exports = mongoose.model('User', userSchema);
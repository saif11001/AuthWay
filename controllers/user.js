const bcrypt = require('bcrypt');
const fs = require("fs");
const path = require("path");

const User = require('../model/user');
const httpStatusText = require('../utils/httpStatusText');

const getAllUsers = async (req, res, next) => {
    const { limit = 10, page = 1, sort = 'createdAt' } = req.query;
    const skip = ( page - 1 ) * limit;
    try{
        const users = await User.find({}, "-password -refreshToken -resetToken -resetTokenExpiration -__v" ).sort(sort).limit(limit).skip(skip);
        if(users.length <= 0) {
            return res.status(200).json({ status: httpStatusText.SUCCESS, data: [], message: "There are no users." })
        }
        
        const totalUsers = await User.countDocuments();
        const totalPages = Math.ceil(totalUsers / limit);

        res.status(200).json({ status: httpStatusText.SUCCESS, data: { users, pagination: { totalUsers, totalPages, currentPage: page } } });
    } catch (error) {
        next(error);
    }
}

const getUser = async (req, res, next) => {
    const userId = req.user.id;
    try{
        const user = await User.findById(userId).select("-__v -password");
        if(!user) {
            const error = new Error('User not found !');
            error.statusCode = 404;
            error.status = httpStatusText.FAIL;
            throw error;
        }
        res.status(200).json({ status: httpStatusText.SUCCESS, data: { user } });
    } catch (error) {
        next(error);
    }
}

const updateUser = async (req, res, next) => {
    const userId = req.user.id;
    const { firstName, lastName, email, password } = req.body;
    try{
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ status: httpStatusText.FAIL, message: "User not found" });
        }

        const updates = {};
        
        if(firstName) { updates.firstName = firstName };
        if(lastName) { updates.lastName = lastName };
        if(email) {
            const oldEmail = await User.findOne({ email })
            if( oldEmail && oldEmail._id.toString() !== userId.toString() ){
                return res.status(409).json({ status: httpStatusText.FAIL, message: 'Email already in use by another user' })
            }
            updates.email = email
        };
        if(password) { updates.password = await bcrypt.hash(password, 12) };
        if (req.file) {
            if (user.avatar) {
                const oldPath = path.join(__dirname, "..", 'uploads', user.avatar);
                fs.unlink(oldPath, (err) => {
                    if (err) console.error("Error deleting old avatar:", err);
                });
            }
            updates.avatar = req.file.filename;
        }

        const updateUser = await User.findByIdAndUpdate(userId, { $set: updates }, { new: true });
        if (!updateUser) {
            return res.status(404).json({ status: httpStatusText.FAIL, message: "User not found" });
        }

        if(password) {
            updateUser.sessions = [];
            await updateUser.save();
            res.clearCookie("accessToken");
            res.clearCookie("refreshToken");

            return res.status(200).json({ status: httpStatusText.SUCCESS, message: "Password updated successfully. Please login again." })
        }
        
        res.status(200).json({ status: httpStatusText.SUCCESS, data: { updateUser } })

    } catch (error) {
        next(error);
    }
}

const deleteUser = async (req, res, next) => {
    const userId = req.user.id;
    try{
        const user = await User.findById(userId);
        if(!user) {
            return res.status(404).json({ status: httpStatusText.FAIL, data: { user: 'User not found' } });
        }
        if (user.avatar) {
            const filePath = path.join(__dirname, "..", "uploads", user.avatar);
            fs.unlink(filePath, (err) => {
                if (err) {
                console.error("Error deleting file:", err);
                } else {
                console.log("Avatar deleted:", user.avatar);
                }
            });
        }

        await user.deleteOne();
        
        res.status(200).json({ status: httpStatusText.SUCCESS, data: { message: 'User deleted successfully' } })
    
    } catch (error) {
        next(error);
    }
}

module.exports = {
    getAllUsers,
    getUser,
    updateUser,
    deleteUser
}

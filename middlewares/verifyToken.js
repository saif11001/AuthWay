const jwt = require('jsonwebtoken');
const httpStatusText = require('../utils/httpStatusText');
const User = require('../model/user');

const verifyToken = async (req, res, next) => {

    const accessToken = req.cookies.accessToken;
    // if(!accessToken) {
    //     return res.status(401).json({ status: httpStatusText.FAIL, message: "Access denied" });
    // }
    try{
        if (accessToken) {
            const decoded = jwt.verify(accessToken, process.env.JWT_SECRET_KEY);
            req.user = decoded;
            return next();
        }    
    } catch (error) {
        if(error.name !== 'TokenExpiredError') {
            return next(error);
        }
    }

    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) {
        return res.status(401).json({ status: httpStatusText.FAIL, message: "Access token expired and no refresh token available." })
    }
    try{
        const decodedRefreshToken = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decodedRefreshToken.id);
        
        if(!user) {
            res.clearCookie("accessToken");
            res.clearCookie("refreshToken");
            return res.status(401).json({ status: httpStatusText.FAIL, message: "Invalid refresh token. Please login again." });
        }
        
        const session = user.sessions.find(s => s.refreshToken === refreshToken);
        if (!session) {
            res.clearCookie("accessToken");
            res.clearCookie("refreshToken");
            return res.status(401).json({
                status: httpStatusText.FAIL,
                message: "Refresh token not recognized. Please login again."
            });
        }

        const newAccessToken = jwt.sign({ id: user._id, email: user.email, userRole: user.userRole }, process.env.JWT_SECRET_KEY, { expiresIn: '15m' } );
        const newRefreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });

        session.refreshToken = newRefreshToken;
        session.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        
        await user.save();

        res.cookie("accessToken", newAccessToken, {
            httpOnly: true,
            // secure: true,
            sameSite: "lax",
            maxAge: 15 * 60 * 1000,
        })
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            // secure: true,
            sameSite: "lax",
            maxAge: 30 * 24 * 60 * 60 * 1000,
        })

        // req.user = jwt.decode(newAccessToken);
        req.user = jwt.verify(newAccessToken, process.env.JWT_SECRET_KEY);
        next();

    }catch (error) {
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        next(error);
    }
}

module.exports = verifyToken;

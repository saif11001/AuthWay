const jwt = require('jsonwebtoken');
const httpStatusText = require('../../utils/httpStatusText');
const User = require('../../model/user');
const config = require('../../config/index');

const verifyToken = async (req, res, next) => {

    const accessToken = req.cookies.accessToken;
    // if(!accessToken) {
    //     return res.status(401).json({ status: httpStatusText.FAIL, message: "Access denied" });
    // }
    try{
        if (accessToken) {
            const decoded = jwt.verify(accessToken, config.jwtSecret.key);
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
        const decodedRefreshToken = jwt.verify(refreshToken, config.jwtRefresh.key);
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

        const newAccessToken = jwt.sign({ id: user._id, email: user.email, userRole: user.userRole }, config.jwtSecret.key, { expiresIn: config.jwtSecret.expiresIn } );
        const newRefreshToken = jwt.sign({ id: user._id }, config.jwtRefresh.key, { expiresIn: config.jwtRefresh.expiresIn });

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
        req.user = jwt.verify(newAccessToken, config.jwtSecret.key);
        next();

    }catch (error) {
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        next(error);
    }
}

module.exports = verifyToken;

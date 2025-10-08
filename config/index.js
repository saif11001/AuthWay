const dotenv = require('dotenv');

dotenv.config();

const config = {
    app: {
        env: process.env.NODE_ENV || "development",
        port: process.env.PORT || 5000,
    },
    db: {
        uri: process.env.MONGO_URI,
    },
    jwtSecret: {
        key: process.env.JWT_SECRET_KEY,
        expiresIn: "15m",
    },
    jwtRefresh: {
        key: process.env.JWT_REFRESH_SECRET,
        expiresIn: "30d",
    },
    mail: {
        ApiKey : process.env.SENDGRID_API_KEY,
        AdminMail: process.env.EMAIL_FROM
    },
    clientUrl: process.env.CLIENT_URL
}

module.exports = config;
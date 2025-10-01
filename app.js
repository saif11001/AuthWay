const path = require('path');
const fa = require('fs');
const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const cookieParser = require("cookie-parser");
const cors = require('cors');
const helmet = require('helmet');

const httpStatusText = require('./utils/httpStatusText');
const logger = require('./middlewares/logger');

const uri = process.env.MONGO_URL;
const port = process.env.PORT;

const app = express();

const uploadsDir = path.join(__dirname, 'uploads');
if (!fa.existsSync(uploadsDir)) {
    fa.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));
app.use(cookieParser());
app.use(express.json());
app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
}));
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "trusted-cdn.com"],
      styleSrc: ["'self'", "fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "cdn.example.com"],
    },
  })
);
const authRouter = require('./routes/auth');
const userRouter = require('./routes/user');

app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.use((error, req, res, next) => {
    logger.error(error);
    const status = error.statusCode || 500;
    const message = error.message || "Something went wrong!";
    const data = error.data || null;
    const errorStatus = error.status || httpStatusText.ERROR;
    res.status(status).json({ message: message, data: data, status: errorStatus });
})

async function main () {
    try{
        await mongoose.connect(uri)
        console.log('Connected to MongoDB');        
        app.listen( port || 5050 , () => {
            console.log('Server is running on port ' + ( port || 5050 ) );
        })
    } catch (error) {
        console.log(error);
    }
}
main()
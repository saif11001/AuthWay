const path = require('path');
const fs = require('fs');
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require("cookie-parser");
const cors = require('cors');
const helmet = require('helmet');

const httpStatusText = require('./utils/httpStatusText');
const logger = require('./middlewares/logger');
const config = require('./config/index');
const { swaggerUi, swaggerSpec } = require("./config/swagger");

const uri = config.db.uri;
const port = config.app.port;

const app = express();

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));
app.use(cookieParser());
app.use(express.json());
app.use(cors({
    origin: config.clientUrl,
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
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const authRouter = require('./routes/auth');
const userRouter = require('./routes/user');

app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.use((error, req, res, next) => {
    logger.error(error.stack || error.message);
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
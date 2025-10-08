const { validationResult } = require('express-validator');
const httpStatusText = require('../../utils/httpStatusText');

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(422).json({ 
            status: httpStatusText.FAIL,
            errors: errors.array()
        });
    };
    next();
};

module.exports = handleValidationErrors;
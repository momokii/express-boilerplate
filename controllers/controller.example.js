const statusCode = require('../utils/http-response').httpStatus_keyValue
const throw_err = require('../utils/throw-err')

// * -------------------------------- CONTROLLERS

exports.example = async (req, res, next) => {
    try{

        res.status(statusCode['200_ok']).json({
            errors: false,
            message: ''
        })
        
    } catch (e) {
        if(!e.statusCode){
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(e)
    }
}
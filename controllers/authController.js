const User = require('../models/users.model')
const statusCode = require('../utils/http-response').httpStatus_keyValue
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const throw_err = require('../utils/throw-err')

// * -------------------------------- CONTROLLERS

exports.login = async (req, res, next) => {
    try{

        const username = req.body.username
        const password = req.body.password

        // * ----- USING MONGO WITH MONGOOSE CHECKING
        const user = await User.findOne({
            username: username
        })
        if(!user){
            throw_err('Wrong Username / Password', statusCode['400_bad_request'])
        }
        // * ----- ----- ----- ----- ----- ----- ----- 

        const check_pass = await bcrypt.compare(password, user.password)
        if(!check_pass){
            throw_err("Wrong Username / Password", statusCode['400_bad_request'])
        }
        
        // * jwt just contain userId with 30days expired time
        const access_token = jwt.sign({
            userId: user._id.toString()
        }, process.env.JWT_SECRET, {
            expiresIn: '30d'
        })

        res.status(statusCode['200_ok']).json({
            errors: false,
            message: 'Login Success',
            data: {
                access_token : access_token,
                token_type: 'Bearer'
            }
        })
        
    } catch (e) {
        if(!e.statusCode){
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(e)
    }
}



exports.signup = async (req, res, next) => {
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
const User = require('../models/users.model') // mongoose
const db = require('../db/db') // postgre
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
        // const user = await User.findOne({
        //     username: username
        // })
        // * ----- ----- ----- ----- ----- ----- ----- 

        // ! ----- USING POSTGRE CHECKING
        let user = (await db.query('SELECT id, username, name, password, role, is_active FROM users WHERE username = $1', [username])).rows[0]
        // ! ----- ----- ----- ----- ----- ----- ----- 

        if(!user) throw_err('Wrong Username / Password', statusCode['400_bad_request'])

        const check_pass = await bcrypt.compare(password, user.password)
        if(!check_pass){
            throw_err("Wrong Username / Password", statusCode['400_bad_request'])
        }
        
        // * jwt just contain userId with 30days expired time
        const access_token = jwt.sign({
            // userId: user._id.toString() // use mongo
            userId: user.id // use mongo // use postgre
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
const jwt = require('jsonwebtoken')
const statusCode = require('../utils/http-response').httpStatus_keyValue
const User = require('../models/users.model') // mongo
const db = require('../db/db') // postgre
const throw_err = require('../utils/throw-err')

module.exports = async (req, res, next) => {
    try {
        
        const authHeader = req.get('Authorization')
        if(!authHeader){
            throw_err('Need Header Auth', statusCode['401_unauthorized'])
        }

        const token = authHeader.split(' ')[1]

        const decode_token = jwt.verify(token, process.env.JWT_SECRET)
        if(!decode_token){
            throw_err('Token Not Valid', statusCode['401_unauthorized'])
        }

        // * ----- USING MONGO WITH MONGOOSE CHECKING
        // const user = await User.findById(decode_token.userId)
        // * ----- ----- ----- ----- ----- ----- ----- 

        // ! ----- USING POSTGRE CHECKING
        const user = (await db.query('SELECT id, username, name, role, is_active FROM users WHERE id = $1', [decode_token.userId])).rows[0]
        // ! ----- ----- ----- ----- ----- ----- ----- 

        if(!user) throw_err('Token Not Valid', statusCode['401_unauthorized'])

        req.userId = decode_token.userId
        req.username = user.username
        req.role = user.role

        next()
    } catch (e) {
        if(!e.statusCode) {
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(e)
    }
}
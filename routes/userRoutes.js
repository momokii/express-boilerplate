const router = require('express').Router()
const userController = require('../controllers/userController')
const { body }  = require('express-validator')
const is_admin = require('../middlewares/role-checking').is_admin
const is_auth = require('../middlewares/is-auth')
const statusCode = require('../utils/http-response').httpStatus_keyValue
const throw_err = require('../utils/throw-err')
const User = require('../models/users.model') // mongoose
const db = require('../db/db') // postgre

// * -------------------------------- routing
router.get('/', is_auth, is_admin, userController.get_all_user)

router.get('/self', is_auth, userController.check_self)

router.get('/:username', is_auth, is_admin, userController.get_user_by_username)

router.post('/', is_auth, is_admin, [
    body('username', 'Username is used, try using another username and username must be alphanumeric')
        .isAlphanumeric()
        .isLength({min: 5})
        .custom((value, {req}) => {
            return (async () => {
                // * ----- USING MONGO WITH MONGOOSE CHECKING
                const user = await User.findOne({
                    username : value
                })
                // * ----- ----- ----- ----- ----- ----- ----- 
                // ! ----- USING POSTGRE CHECKING
                // let user = (await db.query('SELECT id, username, name, password, role, is_active FROM users WHERE username = $1', [value])).rows[0]
                // ! ----- ----- ----- ----- ----- ----- ----- 
                if(user){
                    throw_err(
                        "Username is used, try using another username",
                        statusCode['401_unauthorized'] )
                }
            })()
        }),
    body('password', "Password atleast using 1 number and 1 uppercase with minimum length 6 character")
        .isStrongPassword({
            minLength: 6,
            minNumbers: 1,
            minUppercase: 1,
            minSymbols: 0
        })
], userController.create_user)

router.post('/delete', is_auth, is_admin, userController.delete_user)

router.patch('/password', is_auth, [
    body('new_password', "Password atleast using 1 number and 1 uppercase with minimum length 6 character")
        .isStrongPassword({
            minLength: 6,
            minNumbers: 1,
            minUppercase: 1,
            minSymbols: 0
        })
], userController.change_password)


module.exports = router
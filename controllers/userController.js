const User = require('../models/users.model') // mongo
const db = require('../db/db') // postgre
const statusCode = require('../utils/http-response').httpStatus_keyValue
const throw_err = require('../utils/throw-err')
const { validationResult }  = require('express-validator')
const bcrypt = require('bcrypt')

// * -------------------------------- CONTROLLERS

exports.check_self = async (req, res, next) => {
    try {
        const userId = req.userId

        // * ----- USING MONGO WITH MONGOOSE CHECKING
        const user = await User.findById(userId)
        .select("username name role is_active")
        // * ----- ----- ----- ----- ----- ----- ----- 

        // ! ----- USING POSTGRE CHECKING
        // let user = (await db.query('SELECT id, username, name, role, is_active FROM users WHERE id = $1', [userId])).rows[0]
        // ! ----- ----- ----- ----- ----- ----- ----- 

        if(!user) throw_err('User not found', statusCode['400_bad_request'])

        res.status(statusCode['200_ok']).json({
            errors: false,
            message: 'get self data',
            data: user
        })

    } catch(e) {
        if(!e.statusCode) {
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(exports)
    }
}



exports.get_all_user = async (req, res, next) => {
    try{

        const page = parseInt(req.query.page) || 1 
        const size = parseInt(req.query.per_page) || 10
        const offset = (page - 1) * size 
        const search = req.query.search || ''
        const user_type = req.query.user_type || ''
        let is_active = req.query.is_active || ''
        if(is_active === '1') is_active = true

        // * ----- USING MONGO WITH MONGOOSE
        let query = {
            username: { $regex: search, $options: 'i' },
            role: { $regex: user_type, $options: 'i' }
        }
        const total_user = await User.find(query).countDocuments()
        const user = await User.find(query)
            .select("username name role is_active")
            .skip(offset)
            .limit(size)
        // * ----- ----- ----- ----- ----- ----- ----- 
        // ! ----- USING POSTGRE
        // let query = 'SELECT id, username, name, role, is_active FROM users where 1=1'

        // if(search) query = query + ` and (username ilike '%${search}%' or name ilike '%${search}%')`
        // if(user_type) query = query + ` and role = '${user_type}'`
        
        // let user = await db.query(query)
        // const total_user = user.rowCount
        // user = (user.rows).splice(offset, size)
        // ! ----- ----- ----- ----- ----- ----- ----- 

        if(!user) throw_err("Token Error, User tidak ditemukan", statusCode['404_not_found'])
        

        res.status(statusCode['200_ok']).json({
            errors: false,
            message : "Info user detail",
            data: {
                page: page,
                per_page: size,
                total_data: total_user,
                users: user
            }
        })
        
    } catch (e) {
        if(!e.statusCode){
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(e)
    }
}



exports.get_user_by_username = async (req, res, next) => {
    try{
        const username = req.params.username

        // * ----- USING MONGO WITH MONGOOSE CHECKING
        let user = await User.findOne({
            username: username
        })
            .select('username name role is_active')
        // * ----- ----- ----- ----- ----- ----- ----- 
        // ! ----- USING POSTGRE CHECKING
        // let user = (await db.query('SELECT id, username, name, role, is_active FROM users WHERE username = $1', [username])).rows[0]
        // ! ----- ----- ----- ----- ----- ----- ----- 

        if(!user) throw_err("User not found", statusCode['404_not_found'])
        
        res.status(statusCode['200_ok']).json({
            errors: false,
            message: 'Info User',
            data: user
        })
        
    } catch (e) {
        if(!e.statusCode){
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(e)
    }
}



exports.create_user = async (req, res, next) => {
    try{

        const err_val = validationResult(req)
        if(!err_val.isEmpty()){
            const err_view = err_val.array()[0].msg
            const err = new Error('Add new user Failed - ' + err_view)
            err.statusCode = statusCode['400_bad_request']
            throw err
        }

        const username = req.body.username
        const password = req.body.password
        const hash_password = await bcrypt.hash(password, 16)
        const name = req.body.name
        const role = req.body.role || 'user'

        // * ----- USING MONGO WITH MONGOOSE 
        const new_user = new User({
            username : username,
            password : hash_password,
            name : name,
            role: role
        })

        await new_user.save()
        // * ----- ----- ----- ----- ----- ----- ----- 

        // ! ----- USING POSTGRE CHECKING
        // await db.query('insert into users (username, password, name, role, is_active) values ($1, $2, $3, $4, $5)', [username, hash_password, name, role, true])
        // ! ----- ----- ----- ----- ----- ----- ----- 

        res.status(statusCode['200_ok']).json({
            errors: false,
            message: 'Success create new account'
        })
        
    } catch (e) {
        if(!e.statusCode){
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(e)
    }
}



exports.change_password = async (req, res, next) => {
    // ! ----- USING POSTGRE TRANSACTION
    // const tx = await db.connect()
    // ! ----- ----- ----- ----- ----- ----- ----- 
    try{
        const val_err = validationResult(req)
        if(!val_err.isEmpty()){
            const msg = val_err.array()[0].msg
            throw_err(msg, statusCode['400_bad_request'])
        }

        // * ----- USING MONGO WITH MONGOOSE 
        const user = await User.findById(req.userId)
        // * ----- ----- ----- ----- ----- ----- ----- 

        // ! ----- USING POSTGRE TRANSACTION
        // await tx.query('begin')

        // let user = (await tx.query('SELECT id, username, name, password, role, is_active FROM users WHERE id = $1', [req.userId])).rows[0]
        // ! ----- ----- ----- ----- ----- ----- ----- 
        
        if(!user) throw_err('User not found', statusCode['401_unauthorized'])

        const compare_oldpass = await bcrypt.compare(req.body.password_now, user.password)
        if(!compare_oldpass){
            throw_err("Older password is wrong", statusCode['400_bad_request'])
        }

        const new_pass = await bcrypt.hash(req.body.new_password, 16)

        // * ----- USING MONGO WITH MONGOOSE 
        user.password = new_pass
        await user.save()
        // * ----- ----- ----- ----- ----- ----- ----- 
        // ! ----- USING POSTGRE
        // await tx.query('UPDATE users SET password = $1 WHERE id = $2', [new_pass, req.userId])
        // await tx.query('commit')
        // ! ----- ----- ----- ----- ----- ----- ----- 

        res.status(statusCode['200_ok']).json({
            errors: false,
            message: "User success change password"
        })

    } catch (e) {
        // ! ----- USING POSTGRE
        // await tx.query('rollback')
        // tx.release()
        // ! ----- ----- ----- ----- ----- ----- ----- 
        if(!e.statusCode){
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(e)
    }
}



exports.delete_user = async (req, res, next) => {
    // ! ----- USING POSTGRE TRANSACTION
    // const tx = await db.connect()
    // ! ----- ----- ----- ----- ----- ----- ----- 
    try{    
        const user_id = req.body.user_id

        // * ----- USING MONGO WITH MONGOOSE 
        const check_user = await User.findById(user_id)
        // * ----- ----- ----- ----- ----- ----- ----- 

        // ! ----- USING POSTGRE TRANSACTION
        // await tx.query('begin')

        // let check_user = (await tx.query('SELECT id, username, name, password, role, is_active FROM users WHERE id = $1', [user_id])).rows[0]
        // ! ----- ----- ----- ----- ----- ----- ----- 
        
        if(!check_user) throw_err("User not found", statusCode['404_not_found'])

        if(user_id === req.userId) throw_err("Tidak bisa menghapus akun sendiri", statusCode['400_bad_request'])

        if(req.role !== 'admin') throw_err("Tidak punya akses untuk menghapus user", statusCode['401_unauthorized'])

        
        // * ----- USING MONGO WITH MONGOOSE 
        await User.findByIdAndDelete(user_id)
        // * ----- ----- ----- ----- ----- ----- ----- 
        // ! ----- USING POSTGRE
        // await tx.query('DELETE FROM users WHERE id = $1', [user_id])
        // await tx.query('commit')
        // ! ----- ----- ----- ----- ----- ----- ----- 

        res.status(statusCode['200_ok']).json({
            errors: false,
            message: 'success delete user'
        })
        
    } catch (e) {
        // ! ----- USING POSTGRE
        // await tx.query('rollback')
        // tx.release()
        // ! ----- ----- ----- ----- ----- ----- ----- 
        if(!e.statusCode){
            e.statusCode = statusCode['500_internal_server_error']
        }
        next(e)
    }
}
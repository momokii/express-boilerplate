const router = require('express').Router()
const authController = require('../controllers/authController')

// * -------------------------------- routing

router.post('/login', authController.login)

module.exports = router
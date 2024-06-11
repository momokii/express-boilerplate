const pg = require('pg')

const pool = new pg.Pool ({
    host: process.env.HOST_POSTGRES,
    port: process.env.PORT_POSTGRES,
    user: process.env.USER_POSTGRES,
    password: process.env.PASSWORD_POSTGRES,
    database: process.env.DATABASE_POSTGRES,
    max: 20,
    // idleTimeoutMillis: 30000,
    // connectionTimeoutMillis: 2000,
})

module.exports = pool
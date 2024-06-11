require('dotenv').config()
const express = require('express')
const helmet = require('helmet')
const cors = require('cors')
const bodyParser = require('body-parser')
const yamljs = require('yamljs')
const swaggerUI = require('swagger-ui-express')
const morgan = require('morgan')

const mongoose = require('mongoose') // using mongo
const db = require('./db/db') // using postgres

// * YAML API SPEC
const openAPISpec = yamljs.load('./utils/swagger.yaml')

// * PORTS 
const PORTS = process.env.PORT || 8889

// * ROUTES 
const authRoutes = require('./routes/authRoutes')
const userRoutes = require('./routes/userRoutes')

// * APP ---------------
const app = express()
let serverIsClosing = false;
let server
const apiV1Router = express.Router()

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cors())
app.use(helmet({
    contentSecurityPolicy: false, // disable content security policy
    hidePoweredBy: true, // hide X-Powered-By header
    hsts: false, // { maxAge: 31536000, includeSubDomains: true }, // enable HSTS with maxAge 1 year and includeSubDomains
    noCache: true, // enable noCache header
    referrerPolicy: { policy: 'no-referrer' } // set referrer policy to no-referrer
}))
// * logger middleware for console
const customLogFormat = ':date[iso] | :method | :url | :status | :res[content-length] - :response-time ms'
app.use(morgan(customLogFormat))

// * ROUTING SET
app.use((req, res, next) => {
    if (serverIsClosing) {
        res.status(503).json({
            errors: true,
            message: "Server is shutting down, no new requests accepted."
        });
    } else {
        next();
    }
});
app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(openAPISpec))

apiV1Router.use('/auth', authRoutes)
apiV1Router.use('/users', userRoutes)

app.use('/api/v1', apiV1Router)

// * GLOBAL ERROR HANDLING
app.use((err, req, res, next) => {
    console.log(err) // DEV: log error
    const status = err.statusCode || 500 
    const message = err.message 
    res.status(status).json({
        errors: true, 
        message: message
    })
})


// * ------ APP CONNECTIONS
async function startServer(){
    try{
        // * USING MONGODB WITH MONGOOSE CONNECTION CHECKING
        // await mongoose.connect(process.env.MONGODB_URI)
        // console.log('Connected to mongodb database')

        // * USING POSTGRESQL
        const conn = await db.connect()
        console.log('Connected to postgresql database')
        conn.release()

        server = app.listen(PORTS)
        console.log('Connected, see swagger documentation on http://localhost:' + PORTS + '/api-docs')
    } catch (e){
        console.log(e)
    }
}
startServer()

// * graceful shutdown trigger function
function handleShutdownGracefully(signal) {
    return () => {
        serverIsClosing = true; 

        console.log(`Received ${signal} signal \n Start Closing server gracefully, incoming request will be denied`);

        setTimeout(() => {

            server.close(() => {
                console.log('HTTP server closed gracefully in peace' );
                process.exit(0);
            });

            setTimeout(() => {
                process.exit(1);
            }, 5000); // 5 sec
        }, 10000); // 10 sec
    };
}

// Handle SIGINT 
process.on('SIGINT', handleShutdownGracefully('SIGINT'));
// Handle SIGTERM
process.on('SIGTERM', handleShutdownGracefully('SIGTERM'));
// Handle SIGHUP
process.on('SIGHUP', handleShutdownGracefully('SIGHUP'));
// Handle SIGQUIT
process.on('SIGQUIT', handleShutdownGracefully('SIGQUIT'));

module.exports = app
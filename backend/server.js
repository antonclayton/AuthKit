import express from 'express'
import dotenv from 'dotenv'
import cors from 'cors'
import connect from './src/db/connect.js'
import cookieParser from 'cookie-parser'
import fs from 'node:fs'

dotenv.config()

const port = process.env.PORT || 8000;


const app = express();

//middleware
app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true
}));                                                        // allows server to specify who can access its resources from a different origin or domain
app.use(express.json())
app.use(express.urlencoded({ extended: true }))             // parses incoming requests with URL-encoded payloads. used when submitting form data with POST method (helps extract form data and makes it available through req.body)
app.use(cookieParser())


//routes
const routeFiles = fs.readdirSync('./src/routes')           // automatically includes all routes and reduces boilerplate code in server setup

routeFiles.forEach((file) => {
    //use dynamic import
    import(`./src/routes/${file}`)
        .then((route) => {
            app.use('/api/v1', route.default)
        })
        .catch((err) => {
            console.log("Failed to load route file...", err);
        })
})

const server = async () => {
    try {

        await connect();

        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });

    } catch (error) {
        console.log("Failed to start server: ", error.message)
        process.exit(1);                                            // method used to stop node.js process (used to indicate error)
    }
};

server()
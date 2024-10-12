import asyncHandler from 'express-async-handler'
import jwt from 'jsonwebtoken'
import User from '../models/auth/UserModel.js';
import { StatusCodes } from 'http-status-codes';

export const protect = asyncHandler(async (req, res, next) => {
    try {
        //check if user is logged in
        const token = req.cookies.token;        // gets token from user's cookies

        if (!token) {
            // 401 unauthorized
            res.status(StatusCodes.UNAUTHORIZED).json({ message: "Not authorized, please login" })
        }

        // verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        // get user details from the token ---> exclude password
        const user = await User.findById(decoded.id).select("-password")        // select everything except password

        if (!user) {
            res.status(StatusCodes.NOT_FOUND).json({ message: "User not found" })
        }

        // set user details in the request object
        req.user = user;

        next()


    } catch (error) {
        // 401 unauthorized
        res.status(StatusCodes.UNAUTHORIZED).json({ message: "Not authorized, token failed..." })
    }
})




// admin middleware
export const adminMiddleware = asyncHandler(async (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        // if user is admin, move to the next middleware/controller
        next();
        return;
    }
    // if not admin, send 403 forbidden (terminate request)
    res.status(StatusCodes.FORBIDDEN).json({ message: "Restricted to admins only" })
})




export const creatorMiddleware = asyncHandler(async (req, res, next) => {
    if ((req.user && req.user.role === 'creator') || (req.user && req.user.role === 'admin')) {
        next()
        return
    }

    // if not admin or creator (terminate request)
    res.status(StatusCodes.FORBIDDEN).json({ message: "Only creators can do this"})
});



export const verifiedMiddleware = asyncHandler(async (req, res, next) => {
    if (req.user && req.user.isVerified) {
        next()
        return
    }
    // if not verified, send 403 forbidden --> terminate the request
    res.status(StatusCodes.FORBIDDEN).json({ message: "Please verify your email address"})
})
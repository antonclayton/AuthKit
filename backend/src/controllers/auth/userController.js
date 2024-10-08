import asyncHandler from 'express-async-handler'
import { StatusCodes } from 'http-status-codes'
import User from '../../models/auth/UserModel.js'
import generateToken from '../../helpers/generateToken.js'
import bcrypt from 'bcrypt'

export const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;


    //validation
    if (!name || !email || !password) {
        //400 bad request
        res.status(StatusCodes.BAD_REQUEST).json({ message: 'All fields are required' })
    }

    //check password length
    if (password.length < 6) {
        return res
            .status(StatusCodes.BAD_REQUEST)
            .json({ message: "Password must be at least 6 characters" })
    }

    // check if user already exists
    const userExists = await User.findOne({ email });

    // console.log(userExists);
    if (userExists) {
        //bad request 400
        return res.status(StatusCodes.BAD_REQUEST).json({ message: "User already exists" });
    }

    // create new user 
    const user = await User.create({
        name,
        email,
        password,
    });

    //generate token with user id
    const token = generateToken(user._id);

    // send back user and token in the response to the client
    res.cookie("token", token, {
        path: '/',
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000,
        sameSite: true,
        secure: true,
    })

    if (user) {
        const { _id, name, email, role, photo, bio, isVerified } = user

        // 201 created
        res.status(StatusCodes.CREATED).json({
            _id,
            name,
            email,
            role,
            photo,
            bio,
            isVerified,
            token,  // add token to user
        });
    } else {
        res.status(StatusCodes.BAD_REQUEST).json({ message: "Invalid user data" })
    }
})


// user login
export const loginUser = asyncHandler(async (req, res) => {
    // get email and password from req body
    const { email, password } = req.body;

    if (!email || !password) {
        // 400 Bad Request
        return res.status(StatusCodes.BAD_REQUEST).json({ message: "All fields are required" })
    }

    //check if user exists
    const userExists = await User.findOne({ email })

    if (!userExists) {
        res.status(StatusCodes.NOT_FOUND).json({ message: "User not found, sign up!" })
    }

    //check if the password matches the hashed password in db
    const isMatch = await bcrypt.compare(password, userExists.password)

    if (!isMatch) {
        return res.status(StatusCodes.BAD_REQUEST).json({ message: "Invalid credentials" })
    }

    // generate token with userid
    const token = generateToken(userExists._id)

    if (userExists && isMatch) {
        const { _id, name, email, role, photo, bio, isVerified } = userExists;

        res.cookie("token", token, {
            path: '/',
            httpOnly: true,
            maxAge: 30 * 24 * 60 * 60 * 1000,
            sameSite: true,
            secure: true,
        })

        // send back user and token in the response back to the client
        res.status(StatusCodes.OK).json({
            _id,
            name,
            email,
            role,
            photo,
            bio,
            isVerified,
        })
    } else {
        res.status(StatusCodes.BAD_REQUEST).json({ message: "Invalid email or password" })
    }
})
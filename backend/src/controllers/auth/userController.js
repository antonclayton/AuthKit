import asyncHandler from "express-async-handler";
import { StatusCodes } from "http-status-codes";
import User from "../../models/auth/UserModel.js";
import generateToken from "../../helpers/generateToken.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Token from "../../models/auth/Token.js";
import crypto from "node:crypto";
import hashToken from "../../helpers/hashToken.js";
import sendEmail from "../../helpers/sendEmail.js";

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////***********************************************************************************************************************//////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  //validation
  if (!name || !email || !password) {
    //400 bad request
    res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "All fields are required" });
  }

  //check password length
  if (password.length < 6) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "Password must be at least 6 characters" });
  }

  // check if user already exists
  const userExists = await User.findOne({ email });

  // console.log(userExists);
  if (userExists) {
    //bad request 400
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "User already exists" });
  }

  // create new user
  const user = await User.create({
    name,
    email,
    password, //hashed by User schema
  });

  //generate token with user id
  const token = generateToken(user._id);

  // send back user and token in the response to the client
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000,
    sameSite: true,
    secure: true,
  });

  if (user) {
    const { _id, name, email, role, photo, bio, isVerified } = user;

    // 201 created
    res.status(StatusCodes.CREATED).json({
      _id,
      name,
      email,
      role,
      photo,
      bio,
      isVerified,
      token, // add token to user
    });
  } else {
    // 400 bad request
    res.status(StatusCodes.BAD_REQUEST).json({ message: "Invalid user data" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////***********************************************************************************************************************//////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// user login
export const loginUser = asyncHandler(async (req, res) => {
  // get email and password from req body
  const { email, password } = req.body;

  if (!email || !password) {
    // 400 Bad Request
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "All fields are required" });
  }

  //check if user exists
  const userExists = await User.findOne({ email });

  if (!userExists) {
    res
      .status(StatusCodes.NOT_FOUND)
      .json({ message: "User not found, sign up!" });
  }

  //check if the password matches the hashed password in db
  const isMatch = await bcrypt.compare(password, userExists.password);

  if (!isMatch) {
    // 400 bad request
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "Invalid credentials" });
  }

  // generate token with userid
  const token = generateToken(userExists._id);

  if (userExists && isMatch) {
    const { _id, name, email, role, photo, bio, isVerified } = userExists; // destructuring user (if user exists and token matches)

    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: true,
      secure: true,
    });

    // send back user and token in the response back to the client
    res.status(StatusCodes.OK).json({
      _id,
      name,
      email,
      role,
      photo,
      bio,
      isVerified,
    });
  } else {
    res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "Invalid email or password" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////***********************************************************************************************************************//////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// log out user
export const logoutUser = asyncHandler(async (req, res) => {
  res.clearCookie("token"); // clearing cookies created in register and login

  res.status(StatusCodes.OK).json({ message: "user logged out" });
});

// get user
export const getUser = asyncHandler(async (req, res) => {
  // get user details from the token --> exclude password
  const user = await User.findById(req.user._id).select("-password"); // deselect password
  if (user) {
    res.status(StatusCodes.OK).json(user);
  } else {
    // 404 not found
    res.status(StatusCodes.NOT_FOUND).json({ message: "User not found" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////***********************************************************************************************************************//////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// update user
export const updateUser = asyncHandler(async (req, res) => {
  // get user details from the token ---> exclude passsword
  const user = await User.findById(req.user._id);

  if (user) {
    // user properties to update
    const { name, photo, bio } = req.body;

    //update
    user.name = name || user.name;
    user.photo = photo || user.photo;
    user.bio = bio || user.bio;

    const updated = await user.save();

    res.status(StatusCodes.OK).json({
      _id: updated._id,
      name: updated.name,
      email: updated.email,
      role: updated.role,
      photo: updated.photo,
      bio: updated.bio,
      isVerified: updated.isVerified,
    });
  } else {
    // 404 not found
    res.status(StatusCodes.NOT_FOUND).json({ message: "User not found" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////***********************************************************************************************************************//////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const getAllUsers = asyncHandler(async (req, res) => {
  try {
    const users = await User.find({}); // find all

    if (!users) {
      res.status(StatusCodes.NOT_FOUND).json({ message: "No users found" });
    }

    res.status(StatusCodes.OK).json(users);
  } catch (error) {
    res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ message: "Cannot get users" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////***********************************************************************************************************************//////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const userLoginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "Not authorized, please login..." });
  }

  // verify the token
  const decoded = jwt.verify(token, process.env.JWT_SECRET);

  if (decoded) {
    res.status(StatusCodes.OK).json(true);
  } else {
    res.status(StatusCodes.UNAUTHORIZED).json(false);
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////***********************************************************************************************************************//////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// verify email
export const verifyEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id); // req.user is coming from protect middleware (which verifies jwt token)

  // if user exists
  if (!user) {
    return res
      .status(StatusCodes.NOT_FOUND)
      .json({ message: "User not found" });
  }

  // check if user is verified
  if (user.isVerified) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "User is already verified" });
  }

  let token = await Token.findOne({ userId: user._id });

  // if token exists --> delete the token
  if (token) {
    await Token.deleteOne();
  }

  // create a verification token using the user id ---> crypto
  const verificationToken = crypto.randomBytes(64).toString("hex") + user._id;

  // hash the verification token
  const hashedToken = await hashToken(verificationToken);

  await new Token({
    userId: user._id,
    verificationToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000,
  }).save();

  // verification link
  const verificationLink = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;

  // send email to the user (node mailer)
  const subject = "Email Verification - AuthKit";
  const send_to = user.email;
  const reply_to = "noreply@gmail.com";
  const template = "emailVerification";
  const send_from = process.env.USER_EMAIL;
  const name = user.name;
  const link = verificationLink;

  try {
    //order matters --> subject, send_to, send_from, reply_to,template,
    await sendEmail(
      subject,
      send_to,
      send_from,
      reply_to,
      template,
      name,
      link
    );
    return res.status(StatusCodes.OK).json({ message: "Email sent" });
  } catch (error) {
    console.log("Error sending email: ", error);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ message: "Email could not be sent" });
  }
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////***********************************************************************************************************************//////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// verify user
export const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  if (!verificationToken) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "Invalid Verification Token" });
  }

  // hash the verification token --> because it was hashed before saving
  const hashedToken = hashToken(verificationToken);

  //find user with the verification token
  const userToken = await Token.findOne({
    verificationToken: hashedToken,
    // check if the token is expired
    expiresAt: { $gt: Date.now() },
  });

  // console.log(userToken);

  //invalid or expired
  if (!userToken) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "Invalid or Expired Token" });
  }

  //find user with the userId of the token
  const user = await User.findById(userToken.userId);

  if (user.isVerified) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "User is already verified" });
  }

  // update user to verified
  user.isVerified = true;
  await user.save();
  res.status(StatusCodes.OK).json({ message: "User is verified" });
});

export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "Email is required" });
  }

  // check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    // 404 not found
    return res.status(StatusCodes.NOT_FOUND);
  }

  // see if reset token exists
  let token = await Token.findOne({ userId: user._id });

  // if token exists --> delete the token
  if (token) {
    await Token.deleteOne();
  }

  // create a reset token using the user id --> expires in 1 hours
  const passwordResetToken = crypto.randomBytes(64).toString("hex") + user._id;

  const hashedToken = hashToken(passwordResetToken);

  await new Token({
    userId: user._id,
    passwordResetToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * 60 * 1000,
  }).save();

  // reset link
  const resetLink = `${process.env.CLIENT_URL}/reset-password/${passwordResetToken}`;

  console.log("Original Token:", passwordResetToken);
  console.log("Hashed Token (Saving):", hashedToken);

  // send email to user
  const subject = "Password Reset - Authkit";
  const send_to = user.email;
  const send_from = process.env.USER_EMAIL;
  const reply_to = "noreply@noreply.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetLink;

  console.log(subject, send_to, send_from, reply_to, template, name, link);

  try {
    await sendEmail(
      subject,
      send_to,
      send_from,
      reply_to,
      template,
      name,
      link
    );
    res.json({ message: "Email sent" });
  } catch (error) {
    console.log("Error sending email: ", error);
    return res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ message: "Email could not be sent" });
  }
});

export const resetPassword = asyncHandler(async (req, res) => {
  const { passwordResetToken } = req.params;
  const { password } = req.body;

  // if token doesnt exist
  if (!passwordResetToken) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "Invalid Reset Token" });
  }

  // if password not provided
  if (!password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .json({ message: "Password is required" });
  }

  // hash reset token
  const hashedToken = hashToken(passwordResetToken);

  // check if token exists and still valid
  const userToken = await Token.findOne({
    passwordResetToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  })

  if (!userToken) {
    return res.status(StatusCodes.BAD_REQUEST).json({ message: "Invalid or expired reset token"})
  }

  // find user with the user id in the token
  const user = await User.findById(userToken.userId)

  // update user password (password comes hashed already because of the pre method in UserSchema)
  user.password = password;
  await user.save();

  res.status(StatusCodes.OK).json({ message: "Password Reset Successfully" });

});

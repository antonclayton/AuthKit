import asyncHandler from "express-async-handler";
import { StatusCodes } from "http-status-codes";
import User from "../../models/auth/UserModel.js";


export const deleteUser = asyncHandler(async (req, res) => {
    const { id } = req.params

    // attempt to find and delete user
    try {
        const user = await User.findByIdAndDelete(id)
    
    // if user doesnt exist
    if (!user) {
        return res.status(StatusCodes.NOT_FOUND).json({ message: "User not found"})
    }

    // delete user
    res.status(StatusCodes.OK).json({ message: "Deleted User"})
    } 
    catch (error) {
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: "Cannot delete user"})
    } 



})
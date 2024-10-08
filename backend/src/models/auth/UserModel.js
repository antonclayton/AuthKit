import mongoose from 'mongoose'

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please provide your name']
        ,
    },
    email: {
        type: String,
        required: [true, "Please provide email"],
        unique: true,
        trim: true,
        match: [/^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/, "Please provide valid email"]
    },
    password: {
        type: String,
        required: [true, "Please provide password"],
    },
    photo: {
        type: String,
        default: 'https://avatars.githubusercontent.com/u/19819005?v=4',
    },
    bio: {
        type: String,
        default: "I am a new user!"
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'creator'],
        default: 'user',
    },
    isVerified: {
        type: Boolean,
        default: false,
    }
}, {timestamps: true, minimize: true}); // timestamps tracks timestamps of when user is created | minimize removes empty objects from the documents created by the schema (save space)

const User =  mongoose.model('User', UserSchema)
export default User;
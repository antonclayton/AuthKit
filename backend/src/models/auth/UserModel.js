import mongoose from 'mongoose'
import bcrypt from 'bcrypt'

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

// hash password before saving
UserSchema.pre("save", async function (next){
    //check if password is not modified
    if (!this.isModified("password")) {
        return next();
    }

    //hash password ==> bcrypt
    //generate salt
    const salt = await bcrypt.genSalt(10);
    
    // hash the password with the salt
    const hashedPassword = await bcrypt.hash(this.password, salt);

    //set the password to the hashedpassword
    this.password = hashedPassword

    //call next middleware
    next();

})



const User =  mongoose.model('User', UserSchema)
export default User;
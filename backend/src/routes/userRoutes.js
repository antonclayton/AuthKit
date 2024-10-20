import express from 'express'
import { registerUser, loginUser, logoutUser, getUser, updateUser, getAllUsers, userLoginStatus, verifyEmail, verifyUser} from '../controllers/auth/userController.js'
import { protect, adminMiddleware, creatorMiddleware} from '../middleware/authMiddleware.js'
import { deleteUser } from '../controllers/auth/adminController.js'

const router = express.Router();

// router.route('/').get(getTest)

router.post('/register', registerUser)
router.post('/login', loginUser)
router.get('/logout', logoutUser)

router.route('/user').get(protect, getUser).patch(protect, updateUser)  // same route (code more concise this way)


//admin route
router.delete("/admin/users/:id", protect, adminMiddleware, deleteUser)


// get all users
router.get("/admin/users", protect, creatorMiddleware, getAllUsers)


// login status
router.get("/login-status", userLoginStatus);

// verify user --> email verification (node mailer)
router.post("/verify-email", protect, verifyEmail)

// verify user?
router.post("/verify-user/:verificationToken", verifyUser)


export default router
import express from 'express'
import {registerUser, loginUser} from '../controllers/auth/userController.js'

const router = express.Router();

// router.route('/').get(getTest)

router.post('/register', registerUser)
router.post('/login', loginUser)

export default router
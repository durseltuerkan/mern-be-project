import express from 'express'
import { register, login, logout, verifyOTP, verifyEmail, isAuthenticated, sendResetOtp, resetPassword} from '../controller/authController.js'
import userAuth from '../middleware/userAuth.js';

const authRouter = express();

authRouter.post('/register', register)
authRouter.post('/login', login)
authRouter.post('/logout', logout)
authRouter.post('/send-verify-otp',userAuth, verifyOTP)
authRouter.post('/verify-account', userAuth, verifyEmail)
authRouter.post('/is-auth', userAuth, isAuthenticated)
authRouter.post('/send-reset-otp', sendResetOtp)
authRouter.post('/reset-password', resetPassword)


/*
authRouter
.post('/change-username', 
        userAuth(* das bringt mir userId* Middleware), 
        changeUserName)

        mit user-id braucht man middleware, aber wenn bspw email von req.body geholt wird, dann ist middleware nicht notwendig
*/
export default authRouter
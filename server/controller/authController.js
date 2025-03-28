import userModel from "../models/userModel.js";
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import transporter from "../config/nodemailer.js";


export const register = async (req, res) => {
    const {name, email, password} = req.body
    if(!name || !email || !password){
        return res.json({success:false, message: "All fields are required"})
    }
    try {
        const existingUser = await userModel.findOne({email})
        if(existingUser){
            return res.json({success:false, message:"User alraedy exists"})
        }
        const hashedPassword = await bcrypt.hash(password, 10)
        const user = await userModel.create({name, email, password:hashedPassword})
    
        await user.save()

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET,{ expiresIn: '7d' })
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", //false
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict", //for CORS
            maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
        })
        const mailOptions = {
            from: process.env.SENDER_EMAIL, //sender address
            to: email, //list of receivers
            subject: "Account Verification ✅", // Subject line
            text: `Your account has been created with email: ${email}`, // plain text body
          };
          await transporter.sendMail(mailOptions)
          
        return res.status(200).json({success:true, message:"User created!!"})
        
    } catch (error) {
            res.json({
                success:false, 
                message:error.message
            })
    }
}
export const login = async (req, res) => {
    const { email, password } = req.body;
    if(!email || !password) {
        return res.json({success: false, message: 'All fields are required'})
    }
    try {
        const user = await userModel.findOne({email});
        if(!user) {
            return res.json({success: false, message: 'User does not exist'})
        }
        const isPasswordMatch = await bcrypt.compare(password, user.password )
                                                    //  123    , "$2b$10$QBvh..."
        if(!isPasswordMatch) {
            return res.json({success: false, message: 'Invalid credentials'})
        }
        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET,{ expiresIn: '7d' })
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", //false
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict", //for CORS
            maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
        })
        return res.status(200).json({success: true, message: 'User logged in successfully🎉'})
    } catch (error) {
        res.json({
            success: false,
            message: error.message
        })
    }

}

export const logout = async (req,res) => {
    try {
       res.clearCookie('token',{
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", //false
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict", //for CORS
        
    })
    return res.json({success: true, message: 'Logged out!'})

    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

export const verifyOTP = async (req, res) => {
    const { userId } = req.body;
    if(!userId){
        return res.json({message:"userId not found!"})
    }
    try {
        const user = await userModel.findById(userId);
        if(user.isAccountVerified) {
            return res.status(201).json({success: false, message: 'User is already verified'})
        }
        //otp soll als string gespeichert werden, entweder mit string-method oder backticks
        const otp = `${Math.floor(100000 + Math.random() * 900000)}` ;
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 1000 * 60 * 15
        user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL, //sender address
            to: user.email, //list of receivers
            subject: "Account Verification OTP ✅", // Subject line
            text: `Your OTP is : ${otp}. Verify yor Account‼️`, // plain text body
          };
          await transporter.sendMail(mailOptions)
          return res.status(200).json({success:true, message: 'OTP sent🎊'})

    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export const verifyEmail = async (req,res) => {
    const { userId, otp } = req.body;
    if(!userId || !otp) {
        return res.status(401).json({success: false, message: 'All fields are required'})
    }
    try {
       const user = await userModel.findById(userId);
       if(!user) {
        return res.json({success:false, message: 'User not found'})
       }
       if(user.verifyOtp === "" || user.verifyOtp !== otp) {
        return res.json({success: false, message: 'OTP is invalid'})
       }
       if(user.verifyOtpExpireAt < Date.now()) {
        return res.json({success: false, message: 'OTP has expired. Please request a new one'})
       }
       user.isAccountVerified = true;
       user.verifyOtp = '';
       user.verifyOtpExpireAt = 0;
       user.save();
       return res.json({success: true, message: 'Email is verified ✅'})
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export const isAuthenticated = async (req, res) => {
    try {
        return res.json({success: true, message: 'Authenticated'})
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export const sendResetOtp = async (req,res) => {
    const { email } = req.body;
    if(!email) {
        return res.json({success: false, message: 'Email is required!'})
    }
    try {
        const user = await userModel.findOne({email}) //{email: user@email.com}
        if(!user) {
            return res.json({success: false, message: ' User not found!'})
        }
        const otp = `${Math.floor(100000 + Math.random() * 900000)}` ;
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 1000 * 60 * 15
        user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL, //sender address
            to: user.email, //list of receivers
            subject: "Password reset OTP ✅", // Subject line
            html:`<p>Your OTP is : ${otp}. Change your password‼️</p> <p><i>If you did not request, you can ignore it!<i/></p>` 
          };
          await transporter.sendMail(mailOptions)
          return res.json({success: true, message: 'OTP was sent to your email!'})
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

export const resetPassword = async (req, res) => {
    const { email, password, otp } = req.body;
    if(!email || !password || !otp) {
        return res.json({success: false, message: 'All fields are required!'})
    }
    try {
        const user = await userModel.findOne({email});
        if(!user) {
            return res.json({success: false, message: 'User not found!'})
        }
        if(user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({success: false, message: 'Invalid Otp'})
        }
        if(user.resetOtpExpireAt < Date.now()) {
            return res.json({success: false, message: 'Otp is expired, try a new one.'})
        }
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL, // sender address
            to: user.email, // list of receivers
            subject: "Password successfulyy changed", // Subject line
             // plain text body
             html:`<p>${user.email} password has been changed</p>` 
          };
          await transporter.sendMail(mailOptions)

        return res.json({success: true, message: "Password reseted successfully"})
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}
import mongoose from 'mongoose'


const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase:true,
        trim:true,
        match:[
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/, 
            "Please enter a valid email address"
        ]
    },
    password: {
        type: String,
        required: true,
        match:[
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, 
            "Password is not strong enough"
        ]
    },
    verifyOtp: {
        type: String,
        default: ''
    },
    verifyOtpExpireAt: {
        type: Number,
        default: 0
    },
    isAccountVerified: {
        type: Boolean,
        default: false
    },
    resetOtp: {
        type: String,
        default: ''
    },
    resetOtpExpireAt: {
        type: Number,
        default: 0
    }
})
const userModel = mongoose.models.user || mongoose.model('user', userSchema)

export default userModel;
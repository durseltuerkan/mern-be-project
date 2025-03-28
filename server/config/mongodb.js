import mongoose from 'mongoose'

const connectDB = async() => {
    
    await mongoose.connection.on('connected', () => {
        console.log('Database connected');
        
    })
    await mongoose.connect(`${process.env.MONGODB_URI}/mern-project`)
}

export default connectDB
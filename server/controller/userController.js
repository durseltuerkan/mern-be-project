import userModel from "../models/userModel.js";


export const getUserData = async (req, res) => {
    const { userId } = req.body;
  try {
      const user = await userModel.findById(userId);
      if(!user) {
          return res.json({success: false, message: 'User not found'})
      }
      return res.json({
        success: true,
        name: user.name,
        email: user.email,
        isAccountVerified: user.isAccountVerified
    })
  } catch (error) {
    return res.json({success: false, message: error.message})
  }
}
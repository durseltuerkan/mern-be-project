import jwt from 'jsonwebtoken'

const userAuth = async (req, res, next) => {
    const {token} = req.cookies;
    if(!token) {
        return res.json({success: false, message: 'Unauthorized'})
    }
    console.log(token);
    
    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
        console.log(tokenDecode);
        req.body.userId = tokenDecode.id;
        next()
        
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export default userAuth;
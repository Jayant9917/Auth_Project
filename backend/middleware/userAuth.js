import jwt from "jsonwebtoken";


const userAuth = async (req, res, next) => {
    const { token } = req.cookies;
    
    if(!token){
        return res.json({
            success: false,
            messsage: "Not Authorized. Login Again" 
        })
    }
    try{
        const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET)

        if(tokenDecoded){
            // Ensure req.body is always an object
            if (!req.body) req.body = {};
            req.body.userId = tokenDecoded.id
        }else{
            return res.json({
                success: false,
                message: "Not Authorized. Login Again"
            })
        }
        next();

    }catch(err){
        res.json({
            success: false,
            messsage: err.messsage 
        })
    }
}

export default userAuth;
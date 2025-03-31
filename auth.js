const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;

function auth(req, res, next){
    const token = req.headers.token;

    if(!token){
        return res.status(401).json({
            messsage: "Issue generating token"
        })
    }

    try{
        const decodedData = jwt.verify(token, JWT_SECRET);
        if(decodedData){
            req.userId = decodedData.id;
            next();
        }
    }
    catch(e){
        res.status(403).json({
            message: "Incorrect Credentials"
        })
    }
}

module.exports = {
    auth,
    JWT_SECRET
}
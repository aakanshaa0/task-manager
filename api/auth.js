const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;

function auth(req, res, next){
    const token = req.headers.token || (req.cookies ? req.cookies.token : null);

    if(!token){
        return res.redirect('/signin');
    }

    try{
        const decodedData = jwt.verify(token, JWT_SECRET);
        if(decodedData){
            req.userId = decodedData.id;
            next();
        }
    }
    catch(e){
        res.clearCookie('token');
        res.redirect('/signin');
    }
}

module.exports = {
    auth,
    JWT_SECRET
}

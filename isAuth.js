import jwt from 'jsonwebtoken'

const isAuth = (req) => {
    const authorization = req.headers['authorization'];
    if (!authorization) throw Error ('Please Log In')
    const token = authorization.split(' ')[1];
    const {userID} = jwt.verify(token, process.env.ACCESS_TOKEN_KEY);
    return userID;
}

export default isAuth
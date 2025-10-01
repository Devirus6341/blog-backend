import jwt from 'jsonwebtoken';

const createAccessToken = (userID) => {
    return jwt.sign({userID}, process.env.ACCESS_TOKEN_KEY, {
        expiresIn: '1h'
    })
}

const createRefreshToken = (userID) => {
    return jwt.sign({userID}, process.env.REFRESH_TOKEN_KEY, {
        expiresIn: '7d'
    })
}

const sendRefreshToken = (res, refreshToken) => {
   res.cookie("refreshtoken", refreshToken, {
  httpOnly: true,
  path: "/refresh_token",
  sameSite: "None", 
  secure: true,      
});
}

export {createAccessToken, createRefreshToken, sendRefreshToken}
import jwt from 'jsonwebtoken'
import 'dotenv/config'
import blackList from '../models/blackList.js'

const authUser = async (req, res, next) => {
    const token =
        req.body.token || req.query.token || req.headers['authorization']
    if (!token) {
        return res.status(403).json({
            success: false,
            msg: 'A token is required for authentication',
        })
    }

    try {
        let bearerToken
        if (token.startsWith('Bearer ')) {
            bearerToken = token.split(' ')[1]
            const blackListedToken = await blackList.findOne({
                token: bearerToken,
            })
            if (blackListedToken) {
                return res.status(403).json({
                    success: false,
                    msg: 'this season are expired, please try again',
                })
            }
        } else {
            bearerToken = token
        }

        if (!process.env.ACCESS_TOKEN_SECRECT) {
            throw new Error(
                'ACCESS_TOKEN_SECRET is not defined in the environment variables.'
            )
        }

        const decodeData = jwt.verify(
            bearerToken,
            process.env.ACCESS_TOKEN_SECRECT
        )
        console.log('Decoded token data:', decodeData) // Add this line
        req.user = decodeData.user // Attach decoded data to the request
        return next()
    } catch (error) {
        console.error('Token verification error:', error.message)
        return res.status(403).json({
            success: false,
            msg: 'Invalid tokennnnn',
        })
    }
}

export default authUser

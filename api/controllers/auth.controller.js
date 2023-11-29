import User from '../models/user.model.js'
import bcryptjs from 'bcryptjs'
import { errorHandler } from '../utils/error.js'
import jwt from 'jsonwebtoken'

export const signup = async (req, res, next) => {
    const { username, email, password } = req.body
    const hashedPassword = bcryptjs.hashSync(password, 10)
    const newUser = new User({ username, email, password: hashedPassword })
    try {
        await newUser.save()
        res.status(201).json('Successfully created')
    } catch (e) {
        next(e)
    }
}

export const signin = async (req, res, next) => {
    const { email, password } = req.body
    try {
        const vailUser = await User.findOne({ email })
        if (!vailUser) return next(errorHandler(404, 'User not found'))
        const vailPassword = bcryptjs.compareSync(password, vailUser.password)
        if (!vailPassword) return next(errorHandler(401, 'Wrong credentials'))
        const token = jwt.sign({ id: vailUser._id }, process.env.JWT_SECRET)
        const { password: pass, ...rest } = vailUser._doc
        res.cookie('access_token', token, { httpOnly: true })
            .status(200)
            .json(rest)
    } catch (error) {
        next(error)
    }
}

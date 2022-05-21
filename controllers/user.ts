import { NextFunction, Request, Response } from 'express';
import ApiError from '../errors/ApiError';
import { IUser, User } from '../models';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { where } from 'sequelize';

const generateJwt = (id: number, email: string) => {
    return jwt.sign(
        {id, email},
        String(process.env.SECRET_KEY),
        {expiresIn: '24h'}
    )
}

class UserController {
    async registration(req: Request, res: Response, next: NextFunction) {
        const { username, password } = req.body;
        if (!username || !password) {
            return next(ApiError.badRequest('Некорректный username или password'))
        }
        const candidate = await User.findOne({where: {username}})

        if (candidate) {
            return next(ApiError.badRequest('Пользователь с таким username уже существует'))
        }
        const hashPassword = await bcrypt.hash(password, 5)
        const user = await User.create({username, password: hashPassword}) as any;
        const token = generateJwt(user.id, user.username)
        return res.json({token, user})
    }

    async login(req: Request, res: Response, next: NextFunction) {
        const {username, password} = req.body

        const user = await User.findOne({where: {username}}) as any;
        if (!user) {
            return next(ApiError.badRequest('Пользователь не найден'))
        }
        let comparePassword = bcrypt.compareSync(password, user.password)

        if (!comparePassword) {
            return next(ApiError.badRequest('Указан неверный пароль'))
        }
        const token = generateJwt(user.id, user.username)
        return res.json({token, user})
    }

    async check(req: any, res: Response, next: NextFunction) {
        const candidate = await User.findOne({ where: { id: req.user.id }})
        if (candidate) {
            const token = generateJwt(req.user.id, req.user.username)
            return res.json({token, user: candidate})
        } else {
            next(ApiError.badRequest('Не авторизован'));
        }
    }

    async uploadPhoto(req: any, res: Response, next: NextFunction) {
        const { uri } = req.body;
        if (uri) {
            const user = req.user as IUser;
            const userFromDB = await User.findOne({ where: { id: user.id } });
            await userFromDB?.set({
                photo: uri,
            });
            res.json(await userFromDB?.save());
        }
    }

    async changePassword(req: any, res: Response, next: NextFunction) {
        const { newPassword, password } = req.body;
        const userFromToken = req.user

        const user = await User.findOne({where: {id: userFromToken.id}}) as any;
        let comparePassword = bcrypt.compareSync(password, user.password)
        if (!comparePassword) {
            return next(ApiError.badRequest('Указан неверный пароль'))
        }
        const hashPassword = await bcrypt.hash(newPassword, 5)
        await user.set({
            password: hashPassword
        });

        return res.json(await user.save());
    }

    async changeUsername(req: any, res: Response, next: NextFunction) {
        const { username } = req.body;
        const userFromToken = req.user;

        if (!userFromToken) {
            return next(ApiError.badRequest('Not authorize'))
        }

        const candidate = await User.findOne({where: {username}}) as any;

        if (candidate) {
            return next(ApiError.badRequest('Пользователь с таким именем уже существует'))
        }

        const user = await User.findOne({where: {id: userFromToken.id}}) as any;
        await user.set({
            username,
        });

        return res.json({ token: generateJwt(user.id, username), user: await user.save()});
    }
}

export default new UserController();

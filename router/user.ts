import { Router } from 'express';
import C from '../controllers';
import {AuthMiddleware, FileMiddleware} from '../middlewares';

const router = Router();

router.post('/registration', C.UserController.registration)
router.post('/login', C.UserController.login)
router.get('/auth', AuthMiddleware, C.UserController.check)
router.post('/upload', AuthMiddleware, C.UserController.uploadPhoto)
router.put('/username', AuthMiddleware, C.UserController.changeUsername)
router.put('/password', AuthMiddleware, C.UserController.changePassword)

export default router;

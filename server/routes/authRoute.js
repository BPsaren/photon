import express from 'express';
import userRegister from '../controllers/userRegister.js';
import bodyParser from 'body-parser';

const router = express.Router();
router.use(express.json());
router.use(bodyParser.json());
router.use(bodyParser.urlencoded({ extended: false }));

router.get('/mail-verification', userRegister.mailverification);

router.get('/reset-password', userRegister.resetPassword);
router.post('/reset-password', userRegister.updatePassword);
router.get('/reset-success', userRegister.resetSuccess);

export default router;

import express from 'express'
/* import multer from 'multer';
import path, { dirname } from 'path';
import { fileURLToPath } from 'url'; */
import userRegister from '../controllers/userRegister.js'
import auth from '../middleware/auth.js'
import {
    validateUserRegister,
    sendMailVerificationValidate,
    passwordvalidateValidator,
    loginUserValidation,
    updateProfileValidator,
    otpSendMailVerificationValidate,
    otpVerificationValidate,
} from '../helpers/validation.js'

/* const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename); */

const router = express.Router()
router.use(express.json())

//cd means call back
// Multer configuration
/* const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if(file.mimetype==='image/png' || file.mimetype==='image/jpg'){
            cb(null, path.join(__dirname, '../public/images')); //that is image save folder
        }
        
    },
    filename: function (req, file, cb) {
        const name = Date.now() + '-' + file.originalname;
        cb(null, name);
    },
});

const fileFilter =(req,file,cb)=>{
    if(file.mimetype==='image/png' || file.mimetype==='image/jpg'){
        cb(null,true);
    }else{
        cb(null,false);
    }
}
 */

/* 
const upload = multer({ storage: storage,
    fileFilter:fileFilter
 }); */

// Register route with image upload
//pause for photo
//router.post('/register', upload.single('image'), validateUserRegister,userRegister.userRegister);
router.post('/register', validateUserRegister, userRegister.userRegister)
router.post(
    '/send-mail-verification',
    sendMailVerificationValidate,
    userRegister.sendMmailVerification
)
router.post(
    '/forgot-password',
    passwordvalidateValidator,
    userRegister.forgotPassword
)
router.post('/login', loginUserValidation, userRegister.loginUser)
router.get('/userprofile', auth, userRegister.userProfile)
//pause for second reason photo
//router.post('/update-Profile',auth,updateProfileValidator,upload.single('image'),userRegister.updateProfile);
router.post(
    '/update-Profile',
    auth,
    updateProfileValidator,
    userRegister.updateProfile
)
router.post('/refresh-token', auth, userRegister.refreshToken)
router.get('/logout', auth, userRegister.logOut)
router.post('/send-otp', otpSendMailVerificationValidate, userRegister.sendOtp)
router.post(
    '/otp-verify',
    otpVerificationValidate,
    userRegister.optVerification
)

///Editor add Projects
import projectsController from '../controllers/projects.js' // Import the projects controller
//router.post('/register', validateUserRegister,userRegister.userRegister);
router.post('/addprojects', auth, projectsController.addProjects)

export default router

import mongoose from 'mongoose';
import User from '../models/userModel.js';
import bcrypt from 'bcrypt';
import { validationResult } from 'express-validator';
import mailer from '../helpers/mailer.js';
import randomString from 'randomstring'; // Avoid variable naming conflicts
import PasswordReset from '../models/passwordReset.js';
import passwordReset from '../models/passwordReset.js';
import jwt from 'jsonwebtoken';
import BlackList from '../models/blackList.js';
import OTP from '../models/otp.js';
import {
    oneMinuteOtpExpire,
    threeMinuteOtpExpire,
} from '../helpers/otpvalidate.js';
//for delete photo
import path, { dirname } from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
import deleteFile from '../helpers/deleteFile.js';
import { getDatabaseConnection } from '../utils/db.js';

const userRegister = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                msg: 'Errors',
                errors: errors.array(),
            });
        }

        const { name, email, mobile, password, role } = req.body; // Added role here

        const extingUser = await User.findOne({ email, role });
        if (extingUser) {
            return res.status(400).json({
                success: false,
                msg: `${role} with this email already exits`,
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            mobile,
            password: hashedPassword,
            role,
            isVerified: false,
        });

        await newUser.save();

        // Create dedicated database only for specific roles if needed
        if (role === 'PhotoGrapher' || role === 'Hirer') {
            const userDBName = `${role}_${newUser._id}`;
            await getDatabaseConnection(userDBName);
        }

        const msg = `<p>Hi ${name}, please <a href="http://localhost:3001/mail-verification?id=${newUser._id}">verify</a> your email.</p>`;
        mailer.sendMail(email, 'Email Verification', msg);

        return res
            .status(200)
            .json({ success: true, msg: 'Register Successful' });
    } catch (error) {
        console.log(error);
        return res.status(400).json({ success: false, msg: error.message });
    }
};

const mailverification = async (req, res) => {
    try {
        if (req.query.id === undefined) {
            return res.render('404');
        }

        const userData = await User.findOne({ _id: req.query.id });

        if (userData) {
            if (userData.isVerified) {
                return res.render('mail-verification', {
                    message: 'Your email is already verified',
                });
            }

            await User.findByIdAndUpdate(req.query.id, {
                $set: { isVerified: true },
            });

            return res.render('mail-verification', {
                message: 'Email verified successfully',
            });
        } else {
            return res.render('mail-verification', {
                message: 'User not found',
            });
        }
    } catch (error) {
        console.log(error.message);
        return res.render('404');
    }
};

const sendMmailVerification = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                msg: 'Errors',
                errors: errors.array(),
            });
        }
        const { email } = req.body;

        const userData = await User.findOne({ email });
        if (!userData) {
            return res.status(400).json({
                success: false,
                msg: 'Email does not exist',
            });
        }
        if (userData.isVerified) {
            return res.status(400).json({
                success: false,
                msg: `${userData.email} mail is already verified.`,
            });
        }

        const msg = `<p>Hi ${userData.name}, please <a href="http://localhost:3001/mail-verification?id=${userData._id}">verify</a> your email.</p>`;
        mailer.sendMail(userData.email, 'Email Verification', msg);

        return res.status(200).json({
            success: true,
            msg: 'Verification link sent to your mail. Please check your mail.',
        });
    } catch (error) {
        console.log(error);
        return res.status(400).json({ success: false, msg: error.message });
    }
};

const forgotPassword = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                msg: 'Errors',
                errors: errors.array(),
            });
        }

        const { email } = req.body;
        const userData = await User.findOne({ email });

        if (!userData) {
            return res.status(400).json({
                success: false,
                msg: 'Email does not exist',
            });
        }

        const token = randomString.generate();

        const msg = `<p>Hi ${userData.name}, please click <a href="http://localhost:3001/reset-password?token=${token}">to reset your password</a></p>`;
        const passwordReset = new PasswordReset({
            user_ID: userData._id,
            token: token,
        });
        await passwordReset.save();

        mailer.sendMail(userData.email, 'Reset Password', msg);
        return res.status(201).json({
            success: true,
            msg: 'Reset password link sent to your mail. Please check your mail.',
        });
    } catch (error) {
        console.log(error);
        return res.status(400).json({ success: false, msg: error.message });
    }
};

const resetPassword = async (req, res) => {
    try {
        if (req.query.token == undefined) {
            return res.render('404');
        }
        const resetData = await PasswordReset.findOne({
            token: req.query.token,
        });
        if (!resetData) {
            return res.render('404');
        }
        return res.render('reset-password', { resetData });
    } catch (error) {
        return res.render('404');
    }
};

const updatePassword = async (req, res) => {
    try {
        const { user_ID, password, c_password } = req.body;

        const resetData = await PasswordReset.findOne({ user_ID });

        if (password != c_password) {
            return res.render('reset-password', {
                resetData,
                error: 'confirm password not matching',
            });
        }
        const hashpassword = await bcrypt.hash(c_password, 10);
        User.findByIdAndUpdate(
            { _id: user_ID },
            {
                $set: {
                    password: hashpassword,
                },
            }
        );

        await passwordReset.deleteMany({ user_ID });
        return res.redirect('/reset-success');
    } catch (error) {
        return res.render('404');
    }
};

const resetSuccess = async (req, res) => {
    try {
        return res.render('reset-success');
    } catch (error) {
        return res.render('404');
    }
};

const generateAcessToken = async (user) => {
    const token = await jwt.sign(user, process.env.ACCESS_TOKEN_SECRECT, {
        expiresIn: '2h',
    });
    return token;
};

const generateRefreshToken = async (user) => {
    const token = await jwt.sign(user, process.env.ACCESS_TOKEN_SECRECT, {
        expiresIn: '4h',
    });
    return token;
};

/* const loginUser =async(req,res)=>{
  try {


   const errors = validationResult(req);

   if(!errors.isEmpty()){
    return res.status(400).json({
      success:false,
      msg:'errors',
      errors:errors.array(),
    })
   }
   const { email, password, role } = req.body;
   const userData= await User.findOne({email})

  if(!userData) {
    return res.status(400).json({
      success:false,
      msg:'email and password incorrect'
    })
  }
  
  const passwordMatch=await bcrypt.compare(password,userData.password);
  if(!passwordMatch){
  return res.status(400).json({
    success:false,
    msg:'email and password are invalid'
  })
  }

  if(userData.isVerified==false){
    return res.status(400).json({
      success:false,
      msg:'plase verified your account '
    })
  }

const accessToken = await generateAcessToken({user:userData});
const refreshToken = await  generateRefreshToken({user:userData});

console.log(accessToken)
return res.status(400).json({
  success:'true',
  msg:"log in successfull",
  user:userData,
  accessToken:accessToken,
  refreshToken:refreshToken,
  tokenType:'Bearer'

})
    
  } catch (error) {
     console.log(error);
     return res.render('404',{error:'unexpected error'});
  }

} */
const loginUser = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                msg: 'Validation errors',
                errors: errors.array(),
            });
        }

        const { email, password, role } = req.body; // Added role to match your architecture

        // Check user with both email and role (matches your registration logic)
        const userData = await User.findOne({ email, role });
        if (!userData) {
            return res.status(401).json({
                success: false,
                msg: 'Invalid credentials',
            });
        }

        const passwordMatch = await bcrypt.compare(password, userData.password);
        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                msg: 'Invalid credentials',
            });
        }

        if (!userData.isVerified) {
            return res.status(403).json({
                success: false,
                msg: 'Please verify your account',
            });
        }

        const accessToken = await generateAcessToken({ user: userData });
        const refreshToken = await generateRefreshToken({ user: userData });

        // Set refresh token as HTTP-only cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        // For role-specific database initialization
        if (userData.role === 'PhotoGrapher' || userData.role === 'Hirer') {
            const userDBName = `${userData.role}_${userData._id}`;
            await getDatabaseConnection(userDBName); // Initialize user's DB if needed
        }

        return res.status(200).json({
            success: true,
            msg: 'Login successful',
            user: {
                id: userData._id,
                name: userData.name,
                email: userData.email,
                role: userData.role,
            },
            accessToken: accessToken,
            tokenType: 'Bearer',
        });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({
            success: false,
            msg: 'Internal server error',
            error: error.message,
        });
    }
};

/* const userProfile =async(req,res)=>{

    

     try {
      const userData= await req.user.user;  

     return res.status(404).json({
     success:true,
      msg:'user data fetch successfull',
      user:userData,
      
     })
      
     } catch (error) {
          return res.status(402).json({
            succes:false,
            msg:'invalid tokenn'
          })
     }

} */
const userProfile = async (req, res) => {
    try {
        console.log('User Profile Data:', req.user); // Debug logging
        const userData = req.user; // Access directly if the payload has user info
        return res.status(200).json({
            success: true,
            msg: 'User data fetch successful',
            user: userData,
        });
    } catch (error) {
        console.error('User profile error:', error.message); // Debug logging
        return res.status(402).json({
            success: false,
            msg: 'Invalid tokennn',
        });
    }
};

const updateProfile = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                msg: 'Validation errors occurred',
                errors: errors.array(),
            });
        }

        const { name, mobile } = req.body;
        const user_id = req.user.user._id;

        const data = { name, mobile };

        if (req.file !== undefined) {
            // Set new image path
            data.image = 'images/' + req.file.filename;

            // Find the old user and delete the old image
            const oldUser = await User.findOne({ _id: user_id });

            if (oldUser && oldUser.image) {
                const oldFilePath = path.join(
                    process.cwd(),
                    'public',
                    oldUser.image
                ); // Corrected path

                console.log(`Attempting to delete file: ${oldFilePath}`); // Debugging log

                await deleteFile(oldFilePath);
            }
        }

        const userData = await User.findByIdAndUpdate(
            { _id: user_id },
            { $set: data },
            { new: true }
        );

        return res.status(200).json({
            success: true,
            msg: 'User profile updated successfully',
            userData: userData,
        });
    } catch (error) {
        console.error(error);
        return res.status(400).json({
            success: false,
            msg: error.message,
        });
    }
};

const refreshToken = async (req, res) => {
    try {
        const userData = req.user.user._id;
        const accessToken = await generateAcessToken({ user: userData });
        const refreshToken = await generateRefreshToken({ user: userData });

        console.log(accessToken);
        console.log(refreshToken);
        return res.status(400).json({
            success: 'true',
            msg: 'log in successfull',
            user: userData,
            accessToken: accessToken,
            refreshToken: refreshToken,
            tokenType: 'Bearer',
        });
    } catch (error) {
        return res.status(400).json({
            success: false,
            msg: error.message,
        });
    }
};

const logOut = async (req, res) => {
    const token =
        req.body.token || req.query.token || req.headers['authorization'];

    if (!token) {
        return res.status(403).json({
            success: false,
            msg: 'A token is required for authentication',
        });
    }

    try {
        let bearerToken;
        if (token.startsWith('Bearer ')) {
            bearerToken = token.split(' ')[1];
        } else {
            bearerToken = token;
        }

        const newBlackList = new BlackList({
            token: bearerToken,
        });

        await newBlackList.save();

        return res.status(200).json({
            sucess: true,
            msg: 'you are logged out',
        });
    } catch (error) {
        return res.status(400).json({
            success: false,
            msg: error.message,
        });
    }
};

const generateRandomOtp = async () => {
    return Math.floor(1000 + Math.random() * 9000);
};

const sendOtp = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                msg: 'Validation errors',
                errors: errors.array(),
            });
        }

        const { email } = req.body;

        // Find user by email
        const userData = await User.findOne({ email });
        if (!userData) {
            return res.status(400).json({
                success: false,
                msg: 'Email does not exist',
            });
        }

        // Check if user is already verified
        if (userData.isVerified) {
            return res.status(400).json({
                success: false,
                msg: `${userData.email} mail is already verified.`,
            });
        }

        // Generate new OTP
        const g_otp = await generateRandomOtp();

        // Check if the user already has an OTP record
        const oldOtpData = await OTP.findOne({ user_id: userData._id });

        if (oldOtpData) {
            const sendNextOtp = await oneMinuteOtpExpire(oldOtpData.timestamp);
            if (!sendNextOtp) {
                return res.status(400).json({
                    success: false,
                    msg: 'Please try again after some time',
                });
            }
        }

        const cDate = new Date();

        // Update or insert OTP record
        await OTP.findOneAndUpdate(
            { user_id: userData._id },
            { otp: g_otp, timestamp: cDate },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        // Email message
        const msg = `<p>Hi <b>${userData.name}</b>,</br> Your OTP is: <h4>${g_otp}</h4></p>`;

        // Send OTP email
        try {
            await mailer.sendMail(userData.email, 'OTP Verification', msg);
        } catch (mailError) {
            console.error('Mail sending error:', mailError);
            return res
                .status(500)
                .json({ success: false, msg: 'Failed to send OTP email.' });
        }

        return res.status(200).json({
            success: true,
            msg: 'OTP sent to your mail. Please check your inbox.',
        });
    } catch (error) {
        console.error('Error:', error);
        return res
            .status(500)
            .json({ success: false, msg: 'Internal Server Error' });
    }
};

const optVerification = async (req, res) => {
    try {
        const { user_id, otp } = req.body;

        // Validate user_id
        if (!user_id || !mongoose.Types.ObjectId.isValid(user_id)) {
            return res
                .status(400)
                .json({ success: false, message: 'Invalid user ID' });
        }

        // Check if OTP exists
        const otpData = await OTP.findOne({ user_id, otp });

        if (!otpData) {
            return res
                .status(400)
                .json({ success: false, message: 'Invalid OTP or user ID' });
        }

        // Check if OTP is already verified
        if (otpData.isVerified) {
            return res.status(400).json({
                success: false,
                message: 'Your email is already verified',
            });
        }

        // Check if OTP is expired
        const isOTPExpired = await threeMinuteOtpExpire(otpData.timestamp);
        if (isOTPExpired) {
            return res
                .status(400)
                .json({ success: false, message: 'Your OTP has expired!' });
        }

        // Mark user as verified
        await User.findByIdAndUpdate(user_id, { $set: { isVerified: true } });

        return res.status(200).json({
            success: true,
            message: 'Your email has been successfully verified',
        });
    } catch (error) {
        console.error(error.message);
        return res
            .status(500)
            .json({ success: false, message: 'Server error' });
    }
};

export default {
    userRegister,
    mailverification,
    sendMmailVerification,
    forgotPassword,
    resetPassword,
    updatePassword,
    resetSuccess,
    loginUser,
    userProfile,
    updateProfile,
    refreshToken,
    logOut,
    sendOtp,
    optVerification,
};

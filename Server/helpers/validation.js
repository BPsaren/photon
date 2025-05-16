import { check } from 'express-validator';

export const validateUserRegister = [

  check('role', 'Invalid user role')
    .notEmpty()
    .isIn(['SuperAdmin', 'PhotoGrapher', 'Hirer'])
    .withMessage('Role must be one of: SuperAdmin, PhotoGrapher, Hirer'),

  check('name', 'Name should be minimum 6 characters and maximum 15 characters')
    .notEmpty()
    .isLength({ min: 6, max: 15 }),
  
  check('email', 'Enter a valid email')
    .isEmail()
    .normalizeEmail({ gmail_remove_dots: true }),

  check('mobile', 'Mobile number must contain 10 digits')
    .isLength({ min: 10, max: 10 })
    .isNumeric(),

  check('password', 'Password must be at least 6 characters long, include one uppercase letter, one lowercase letter, one number, and one special character')
    .isStrongPassword({
      minLength: 6,
      minUppercase: 1,
      minLowercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    }),
];




export const sendMailVerificationValidate  =[
  check('email', 'Enter a valid email')
  .isEmail().normalizeEmail({ gmail_remove_dots: true }),

  

];
export const passwordvalidateValidator  =[
  check('email', 'Enter a valid email')
  .isEmail().normalizeEmail({ gmail_remove_dots: true }),

  
];


export const loginUserValidation =[

  check('role', 'Invalid user role')
    .notEmpty()
    .isIn(['SuperAdmin', 'PhotoGrapher', 'Hirer'])
    .withMessage('Role must be one of: SuperAdmin, PhotoGrapher, Hirer'),

  check('email', 'Enter a valid email')
  
  .isEmail().normalizeEmail({ gmail_remove_dots: true }),
  check('password', 'Password must be at least 6 characters long, include one uppercase letter, one lowercase letter, one number, and one special character')
  .isStrongPassword({
    minLength: 6,
    minUppercase: 1,
    minLowercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  }),
];


export const updateProfileValidator = [
  check('name', 'Name should be minimum 6 characters and maximum 15 characters'),
    
  
  check('mobile', 'Mobile number must contain 10 digits')
    /* .isLength({ min: 10, max: 10 })
    .isNumeric(), */
   ];


   export const otpSendMailVerificationValidate  =[
    check('email', 'Enter a valid email')
    .isEmail().normalizeEmail({ gmail_remove_dots: true }),
  
    
    
  ];



 export  const otpVerificationValidate =[
  check('user_id', 'user is must be required').not()
  .notEmpty(),
  check('otp', 'otp must be required').not()
  .notEmpty(),
  
 ]
  
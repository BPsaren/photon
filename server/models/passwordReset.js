import mongoose from 'mongoose';

const passwordResetScehma = new mongoose.Schema({
    user_ID: {
        type: String,
        required: true,
        ref: 'User',
    },
    token: {
        type: String,
        required: true,
    },
});

export default mongoose.model('ResetPassword', passwordResetScehma);

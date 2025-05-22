import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
    {
        name: { type: String, required: true },
        email: { type: String, required: true },
        mobile: { type: String, required: true },
        password: { type: String, required: true },
        role: { type: String, enum: ['SuperAdmin', 'PhotoGrapher', 'Hirer'] },
        isVerified: { type: Boolean, default: false },
    },
    { timestamps: true }
);
//for timestamp
//createdAt: This field is automatically set to the current date and time when the document is first created.
//updatedAt: This field is updated to the current date and time every time the document is modified.

// Add compound index to enforce unique email per role
userSchema.index({ email: 1, role: 1 }, { unique: true });
export default mongoose.model('User', userSchema);

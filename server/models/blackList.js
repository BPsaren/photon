import mongoose from 'mongoose';
const blackListSchema = new mongoose.Schema(
    {
        token: {
            type: String,
            required: true,
        },
    },
    {
        timestamps: true,
    }
);

export default mongoose.model('BlackList', blackListSchema);

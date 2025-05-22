import mongoose from 'mongoose'
const bookingSchema = new mongoose.Schema(
    {
        hirerid: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
        },
        photoGrapherId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
        },
        eventType: {
            type: String,
            enum: ['Wedding', 'Birthday', 'Others'],
            required: true,
        },
        date: { type: String, required: true },
        status: {
            type: String,
            enum: ['Pending', 'Confirm', 'Cancelled'],
            default: 'Pending',
        },
    },
    { timestamps: true }
)
export default mongoose.model = bookingSchema

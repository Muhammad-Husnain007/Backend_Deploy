import mongoose, { Schema } from "mongoose";

const contactSchema = new Schema({
    firstName: {
        type: String,
        required: true,
    },
    lastName: {
        type: String,
        required: true,
    },
//     displayProfile: [{
//         profile: {
//         type: Schema.Types.ObjectId,
//         ref: "Profile"
//     },
//         uploaded: {
//             type: Boolean,
//             default: false
//     },
//  }],
    phoneNumber: {
        type: Number,
        required: true,
    },
    user: [{
        type: Schema.Types.ObjectId,
        ref: "User"
    }]

}, { timestamps: true });

export const Contact = mongoose.model('Contact', contactSchema);
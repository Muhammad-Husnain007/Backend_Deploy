import mongoose, { Schema } from "mongoose";

const groupMessageSchema = new Schema({
    group: [{
        type: Schema.Types.ObjectId,
        ref: 'Group'
    }],
    sender: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],
    content: {
        type: String,
        required: true,
    },
   status: {
    type: String,
    enum: ['sent', 'delivered', 'read'],
    default: 'sent'
   },
    messageType: {
        type: String,
        enum: ['text', 'image', 'video'],
        default: 'text'
    },
   media: {
    type: String,
   }
}, { timestamps: true });

export const groupMessage = mongoose.model('groupMessage', groupMessageSchema);
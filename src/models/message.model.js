import mongoose, { Schema } from "mongoose";

const MessageSchema = new Schema({
    chat: [{
        type: Schema.Types.ObjectId,
        ref: 'Chat',
        required: true,
    }],
    sender: [{
       type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    }],
    receiver: [{
       type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,

    }],
    content: {
        type: String,
        required: true,
    },    
    messageType: {
        type: String,
        enum: ['text', 'image', 'video'],
        default: 'text'
    },
    status: {
        type: String,
        enum: ['sent', 'delivered', 'read'],
        default: 'sent'
    },
}, { timestamps: true });

export const Message = mongoose.model('Message', MessageSchema);
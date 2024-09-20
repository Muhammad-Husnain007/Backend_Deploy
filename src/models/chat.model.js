import mongoose, { Schema } from "mongoose";

const chatSchema = new Schema({
    participants: [{
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }],
    chats: [{
        type: Schema.Types.ObjectId,
        ref: 'Message',
    }],
   

}, { timestamps: true });

export const Chat = mongoose.model('Chat', chatSchema);
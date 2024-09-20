import mongoose, { Schema } from "mongoose";

const profileSchema = new Schema({
    profile: {
        type: String,
        required: false
    },
    user: [{
        type: Schema.Types.ObjectId,
        ref: "User"
    }], 
    // contact: [{
    //     type: Schema.Types.ObjectId,
    //     ref: "Contact"
    // }], 

}, { timestamps: true });

export const Profile = mongoose.model('Profile', profileSchema);
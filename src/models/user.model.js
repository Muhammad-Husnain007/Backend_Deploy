import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";

const userSchema = new Schema({
    phoneNumber: {
        type: Number,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    otp: {
        type: String
    },
    contacts: [{
        contact: {
            type: Schema.Types.ObjectId,
            ref: "Contact"
        },
        exists: {
            type: Boolean,
            default: false
        }
    },
    // {
    //     profile: {
    //         type: Schema.Types.ObjectId,
    //         ref: "Contact"
    //     },
    //     uploaded: {
    //         type: Boolean,
    //         default: false
    //     }
    // }
],
    displayProfile: [{
        profile: {
            type: Schema.Types.ObjectId,
            ref: "Profile"
        },
        // uploaded: {
        //     type: Boolean,
        //     default: false
        // }
    }
],

    refreshToken: {
        type: String,
    }
}, { timestamps: true });

userSchema.methods.generateAccessToken = function () {
    return jwt.sign({
        _id: this._id,
        phoneNumber: this.phoneNumber,
    },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
        });
};

userSchema.methods.generateRefreshToken = function () {
    return jwt.sign({
        _id: this._id,
    },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
        });
};

export const User = mongoose.model('User', userSchema);

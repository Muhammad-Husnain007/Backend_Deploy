import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/AsyncHandler.js";
import jwt from "jsonwebtoken";


// JWT token ko verify karne ke liye middleware
export const verifyJwt = asyncHandler(async (req, res, next) => {
    try {
        // Token ko cookies se ya Authorization header se nikalna
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
        
        console.log('Token:', token); // Console mein token ko print karna
        console.log('ACCESS_TOKEN_SECRET:', process.env.ACCESS_TOKEN_SECRET); // Secret key ko console mein print karna

        if (!token) {
            throw new ApiError(401, "Unauthorized request: No token provided"); // Agar token nahi hai, toh error throw karna
        }

        // Token ko verify karna
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        
        console.log('Decoded Token:', decodedToken); // Decoded token ko console mein print karna

        // Decoded token ke user ID se user ko dhoondhna
        const user = await User.findById(decodedToken._id).select("-phoneNumber -refreshToken");

        if (!user) {
            throw new ApiError(401, "Unauthorized request: Invalid user"); // Agar user nahi milta, toh error throw karna
        }

        // User ko request object mein attach karna
        req.user = user;
        next(); // Agle middleware ya route handler ko call karna
    } catch (error) {
        console.error('JWT verification error:', error); // Error ko console mein print karna

        if (error.name === 'JsonWebTokenError') {
            throw new ApiError(401, "Unauthorized request: Invalid access token"); // Agar token invalid hai, toh error throw karna
        } else if (error.name === 'TokenExpiredError') {
            throw new ApiError(401, "Unauthorized request: Expired access token"); // Agar token expire ho gaya hai, toh error throw karna
        }

        throw new ApiError(401, error.message || "Unauthorized request: Authentication failed"); // Dusre errors ke liye generic error throw karna
    }
});


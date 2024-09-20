import { asyncHandler } from "../utils/AsyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { User } from '../models/user.model.js';
import jwt from "jsonwebtoken";
import { Profile } from "../models/profile.model.js";

// Generate access and refresh tokens for a user
const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        if (!user) {
            throw new ApiError(404, "User not found");
        }
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });
        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong");
    }
};

// Refresh the access token using the refresh token
const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies?.refreshToken || req.body.refreshToken;
        if (!incomingRefreshToken) {
            throw new ApiError(401, "Unauthorized Token");
        }

        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decodedToken._id);

        if (!user) {
            throw new ApiError(401, "Invalid Token");
        }

        const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);
        const options = {
            httpOnly: true,
            secure: true,
        };

        res.cookie("accessToken", accessToken, options);
        res.cookie("refreshToken", refreshToken, options);

        return res.status(200).json(
            new ApiResponse(
                200,
                { accessToken, refreshToken },
                "Token Refresh Successful"
            )
        );
    } catch (error) {
        throw new ApiError(401, error.message || "Server Error");
    }
});

// Register a new user and log them in
const registerUser = asyncHandler(async (req, res) => {
    try {
        const { phoneNumber, name, email } = req.body;
        let user = await User.findOne({ phoneNumber });

        if (user) {
            throw new ApiError(400, "User with this phone number already exists");
        }

        user = await User.create({ 
            phoneNumber,
            name: name,
            email: email
         });

        const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);
        const createdUser = await User.findById(user._id).select("-refreshToken");

        const options = {
            httpOnly: true,
            secure: true,
        };

        return res.status(201)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(new ApiResponse(
                201,
                {
                    user: createdUser,
                    accessToken,
                    refreshToken,
                },
                "User created and logged in successfully"
            ));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Retrieve all users and update their contacts and profiles
const getAllUsers = asyncHandler(async (req, res) => {
    try {
        const users = await User.find(req.user)
            .populate('contacts.contact')
            .populate('displayProfile.profile');

        for (const user of users) {
            // Contacts check and update
            for (const contactObj of user.contacts) {
                if (contactObj.contact && !contactObj.exists) {
                    const contactUser = await User.findOne({ 
                        phoneNumber: contactObj.contact.phoneNumber 
                    });

                    if (contactUser) {
                        contactObj.exists = true;
                        contactObj.contact = contactUser._id; 
                    }
                } 
                else if (contactObj.exists && contactObj.contact.user == null) {
                    const contactUser = await User.findOne({ 
                        phoneNumber: contactObj.contact.phoneNumber 
                    });

                    if (contactUser) {
                        contactObj.contact.user = contactUser._id;
                    }
                }
            }

            // Profile check and update
            for (const profileObj of user.displayProfile) {
                if (profileObj.profile && !profileObj.upload) {
                    const profileUser = await User.findOne({ 
                        phoneNumber: profileObj.profile.phoneNumber 
                    });

                    if (profileUser && profileUser.profile.length > 0) {
                        profileObj.upload = true;
                        profileObj.profile = profileUser.profile[0]._id;
                    }
                }
            }

            await user.save();
        }

        return res.status(200).json(new ApiResponse(
            200,
            users,
            "Users retrieved successfully"
        ));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Retrieve a specific user by ID
const getByIdUser = asyncHandler(async (req, res) => {
    try {
        const { userId } = req.params;
        console.log('Fetching user with ID:', userId);

        // Fetch the user with contacts populated
        let user = await User.findById(userId).populate({
            path: 'contacts.contact',
            populate: {
                path: 'user',
                model: 'User',  
                populate: {
                    path: 'displayProfile.profile',
                    model: 'Profile' 
                }
            }
        });

        if (!user) {
            console.error(`User with ID ${userId} not found`);
            throw new ApiError(404, "User not found");
        }

        // Create a new array to store valid contacts
        const validContacts = [];

        // Update contacts if necessary
        for (const contactObj of user.contacts) {
            if (contactObj.contact) {
                // If the contact exists but the contact.user is missing, find and assign it
                if (!contactObj.exists) {
                    const contactUser = await User.findOne({ phoneNumber: contactObj.contact.phoneNumber });
                    if (contactUser) {
                        contactObj.exists = true;
                        contactObj.contact.user = contactUser._id;
                    }
                }

                if (contactObj.exists && !contactObj.contact.user) {
                    const contactUser = await User.findOne({ phoneNumber: contactObj.contact.phoneNumber });
                    if (contactUser) {
                        contactObj.contact.user = contactUser._id;
                    }
                }

                // Push valid contacts to the new array
                validContacts.push(contactObj);

            } 
        }

        // Replace the user's contacts with valid ones
        user.contacts = validContacts;

        await user.save();
        return res.status(200).json(new ApiResponse(200, user, "User getById retrieve successfully"));
    } catch (error) {
        console.error('Error occurred:', error.message);
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Login user with phone number
const loginUser = asyncHandler(async (req, res) => {
    try {
        const { phoneNumber } = req.body;
        if (!phoneNumber) {
            throw new ApiError(400, "Please enter phone Number");
        }
        const user = await User.findOne({ phoneNumber });
        if (!user) {
            throw new ApiError(404, "Phone Number didn't match");
        }
        const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);
        const loggedInUser = await User.findById(user._id).select("-refreshToken");
        const options = {
            httpOnly: true,
            secure: true,
            sameSite: 'None'
 
        };
        return res.status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken,
                },
                "User logged in successfully",
            ));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Logout user by clearing cookies and unsetting the refresh token
const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {  // for remove token
                refreshToken: 1
            }
        },
        {
            new: true
        }
    );

    const options = {
        httpOnly: true, // not access cookie on client side only http
        secure: true ,  // can send secure http connection
        sameSite: 'None'
    };
    return res.status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(
            new ApiResponse(200, {}, "User logged out successfully")
        );
});

// Delete a specific user by ID
const deleteUser = asyncHandler(async (req, res) => {
    try {
        const { userId } = req.params;
        const deleteUser = await User.findByIdAndDelete(userId);

        return res.status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "User deleted successfully"
                )
            );
    } catch (error) {
        throw new ApiError(500, error?.message || "Server error while deleting user data");
    }
});

export {
    registerUser,
    getAllUsers,
    getByIdUser,
    loginUser,
    logoutUser,
    deleteUser,
    refreshAccessToken,
    generateAccessAndRefreshTokens,
};

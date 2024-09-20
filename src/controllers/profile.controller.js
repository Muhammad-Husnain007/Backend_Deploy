import { asyncHandler } from "../utils/AsyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { Profile } from '../models/profile.model.js';
import { User } from '../models/user.model.js';
import { fileUploadCloudinary, deleteFileFromCloudinary } from "../utils/Fileupload.js"
import { Contact } from "../models/contact.model.js";

// Function to handle profile upload and replace the existing profile with a new one
const Uploadprofile = asyncHandler(async (req, res) => {
    try {
        const { userId } = req.params;
        const profileLocalPath = req.files?.profile?.[0]?.path;

        if (!profileLocalPath) {
            throw new ApiError(400, "Profile is required");
        }

        const user = await User.findById(userId).populate('displayProfile.profile');
        if (!user) {
            throw new ApiError(400, "UserId not found");
        }

        let oldProfile = user.displayProfile.find(dp => dp.profile);
        let oldProfileUrl = oldProfile ? oldProfile.profile.profile : null;

        const uploadProfile = await fileUploadCloudinary(profileLocalPath);
        if (!uploadProfile) {
            throw new ApiError(400, "Profile upload to cloud failed");
        }

        if (oldProfileUrl) {
            await deleteFileFromCloudinary(oldProfileUrl); 
        }

        const displayProfile = await Profile.create({ user: userId, profile: uploadProfile.url });

        user.displayProfile = [{ profile: displayProfile._id }];
        
        await user.save();
        return res.status(200).json(
            new ApiResponse(
                200,
                { displayProfile },
                "Profile uploaded successfully"
            )
        );
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Function to retrieve a profile by its profileId
const receiveProfile = asyncHandler(async (req, res) => {
    try {
        const { profileId } = req.params;
        if (!(profileId)) {
            throw new ApiError(400, "UserId not found");
        }
        const getProfile = await Profile.findById(profileId);
        return res.status(201)
            .json(new ApiResponse(
                200, getProfile, "Profile received successfully"
            ));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Function to retrieve the display profile associated with a user by userId
const receiveDP = asyncHandler(async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findById(userId).populate('displayProfile.profile');
        if (!user) {
            throw new ApiError(404, "User not found with this id");
        }
      const profile = user.displayProfile;
        return res.status(201).json(
            new ApiResponse(
                201,
                {profile},
                "Profile by userId received successfully"
            )
        );
    } catch (error) {
        console.error('Error:', error.message);
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

export {
    Uploadprofile,
    receiveProfile,
    receiveDP,
}

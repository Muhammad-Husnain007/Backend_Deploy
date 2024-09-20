import { asyncHandler } from "../utils/AsyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { Contact } from '../models/contact.model.js';
import { User } from '../models/user.model.js';

// Adds a new contact to the user's contacts list. 
// If the contact already exists, throws an error.
const userContact = asyncHandler(async (req, res) => {
    try {
        const { firstName, lastName, phoneNumber } = req.body;
        const { userId } = req.params;

        // Find the user and populate contacts and display profile
        const user = await User.findById(userId)
            .populate('contacts.contact')
            .populate('displayProfile.profile');

        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        // Check if the contact already exists
        const contactExists = user.contacts.some(contactObj => 
            contactObj.contact && contactObj.contact.phoneNumber === phoneNumber
        );

        if (contactExists) {
            throw new ApiError(400, 'Contact already exists');
        }

        // Check if the phone number belongs to an existing user
        const existingUser = await User.findOne({ phoneNumber });
        let userExist = false;
        let contactUserId = null;
        let profile = null;

        if (existingUser) {
            userExist = true;
            contactUserId = existingUser._id;

            // Get existing user's profile if available
            if (existingUser.displayProfile && existingUser.displayProfile.length > 0) {
                profile = existingUser.displayProfile[0].profile || null;
            }
        }

        // Create a new contact and add it to the user's contacts
        const newContact = new Contact({ firstName, lastName, phoneNumber, user: contactUserId, displayProfile: profile });
        await newContact.save();
        user.contacts.push({ contact: newContact._id, exists: userExist });
        await user.save();

        // Return updated contacts
        const updatedUser = await User.findById(userId).populate('contacts.contact').populate('displayProfile.profile');
        return res.status(200).json(new ApiResponse(200, { contact: newContact, updatedContacts: updatedUser.contacts }, "Contact added successfully"));
    } catch (error) {
        console.error('Error:', error); 
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Fetches all contacts, checks if contacts' user field is missing, and updates it if necessary.
const getAllContacts = asyncHandler(async (req, res) => {
    try {
        let contacts = await Contact.find(req.users);
        for (const contact of contacts) {
            if (!contact.user) {
                const user = await User.findOne({ phoneNumber: contact.phoneNumber });
                if (user) {
                    contact.user = user._id;
                    await contact.save(); 
                }
            }
        }
        contacts = await Contact.find(req.users);
        return res.status(200).json(new ApiResponse(200, contacts, "Contacts retrieved and updated successfully"));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Fetches a contact by its ID.
const getByIdContact = asyncHandler(async (req, res) => {
    try {
        const { contactId } = req.params;
        const contact = await Contact.findById(contactId).populate("user");
        return res.status(200).json(new ApiResponse(200, contact, "Contact retrieved successfully"));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Deletes a contact by its ID.
const deleteContact = asyncHandler(async (req, res) => {
    try {
        const { contactId } = req.params;
        const contact = await Contact.findByIdAndDelete(contactId);
        return res.status(200).json(new ApiResponse(200, contact, "Contact deleted successfully"));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

// Updates a contact's details (first name, last name, phone number) by its ID.
const updateContact = asyncHandler(async (req, res) => {
    try {
        const { contactId } = req.params;
        const { firstName, lastName, phoneNumber } = req.body;
        const contact = await Contact.findByIdAndUpdate(contactId, { 
            $set: { firstName, lastName, phoneNumber }
        }, { new: true });
        return res.status(200).json(new ApiResponse(200, contact, "Contact updated successfully"));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

export {
    userContact,
    getAllContacts,
    getByIdContact,
    deleteContact,
    updateContact,
};

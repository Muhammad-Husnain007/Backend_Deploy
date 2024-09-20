import { asyncHandler } from "../utils/AsyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { Chat } from "../models/chat.model.js";
import { User } from "../models/user.model.js";

//  Api: for create chat between two users. get two participants and check user exist if(exist){create chat}

const createChat = asyncHandler(async (req, res) => {
    const { participants } = req.body;

    if (!participants || participants.length !== 2) {
        throw new ApiError(400, "Two participants are required");
    }

    const validParticipants = await User.find({ _id: { $in: participants } });
    if (validParticipants.length !== participants.length) {
        throw new ApiError(400, "Some participants are not valid users");
    }

    const [participant1, participant2] = participants;

    const user1 = await User.findById(participant1).populate('contacts.contact');
    const user2 = await User.findById(participant2).populate('contacts.contact');

    if (!user1 || !user2) {
        throw new ApiError(400, "One or both users do not exist");
    }

    const user1Contacts = user1.contacts.map(contactObj => contactObj.contact.phoneNumber);
    const user2Contacts = user2.contacts.map(contactObj => contactObj.contact.phoneNumber);

    const participant1PhoneNumber = user1.phoneNumber;
    const participant2PhoneNumber = user2.phoneNumber;

    const isUser1InUser2Contacts = user2Contacts.includes(participant1PhoneNumber);
    const isUser2InUser1Contacts = user1Contacts.includes(participant2PhoneNumber);

    if (!isUser1InUser2Contacts && !isUser2InUser1Contacts) {
        throw new ApiError(400, "At least one participant must be in the other's contact list");
    }
    const chat = await Chat.create({ participants });
    return res.status(200).json(
        new ApiResponse(200, chat, "Chat created successfully")
    );
});

//  Api: for get users chats.

const getAllChats = asyncHandler(async (req, res) => {
    try {
        const chats = await Chat.find(req.users);
        return res.status(200)
            .json(new ApiResponse(
                200,
                chats,
                "Chats retrieved successfully"
            ));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

//  Api: for check participants alaredy exists.

const participantsExist = asyncHandler(async (req, res) => {
    try {
        const { participants } = req.body;
    
        const existingChat = await Chat.findOne({
          participants: { $all: participants }
        });
    
        if (existingChat) {
          return res.status(200).json({ success: true, data: existingChat });
        } else {
          return res.status(200).json({ success: false, message: 'No chat found' });
        }
      } catch (error) {
        console.error('Error finding chat:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
}); 

//  Api: for get by id of any chat.

const getByIdChat = asyncHandler(async (req, res) => {
    try {
        const { chatId } = req.params;
        const chat = await Chat.findById(chatId);

        if (!chat) {
            throw new ApiError(404, "Chat not found");
        }
    const populate = await Chat.findById(chatId).populate('participants')
      
        return res.status(200)
            .json(new ApiResponse(
                200,
                populate,
                "Chat retrieved successfully"
            ));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

//  Api: for delete chat between users.

const deleteChat = asyncHandler(async (req, res) => {
    try {
        const { chatId } = req.params;
        const chat = await Chat.findByIdAndDelete(chatId);
        return res.status(200)
            .json(new ApiResponse(
                200,
                chat,
                "Chat deleted successfully"
            ));
    } catch (error) {
        throw new ApiError(500, error?.message || "Something went wrong");
    }
});

export {
    createChat,
    getAllChats,
    getByIdChat,
    deleteChat,
    participantsExist
};

import { Router } from "express";
import { createChat, deleteChat, getAllChats, getByIdChat, participantsExist } from "../controllers/chat.controller.js";
import { verifyJwt } from "../middlewares/auth.middleware.js";


const router = Router();
router.use(verifyJwt);

router.route('/createChat').post(createChat)
router.route('/participantsExist').post(participantsExist)
router.route('/').get(getAllChats)
router.route('/:chatId').get(getByIdChat)
router.route('/:chatId').delete(deleteChat)

export default router

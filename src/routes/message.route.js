import { Router } from "express";
import { deleteMessage, getByIdMessage, receiveMessage, sendMessage, updateMessage } from "../controllers/message.controller.js";

const router = Router();

router.route("/send/:chatId").post(sendMessage)
router.route("/receive/:chatId").get(receiveMessage)
router.route("/update/:messageId").put(updateMessage)
router.route("/getById/:messageId").get(getByIdMessage)
router.route("/delete/:messageId").delete(deleteMessage)

export default router
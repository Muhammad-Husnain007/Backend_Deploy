import { Router } from "express";
import { userContact, getAllContacts, getByIdContact, updateContact, deleteContact } from "../controllers/contact.controller.js";
import { verifyJwt } from "../middlewares/auth.middleware.js";

const router = Router();
router.use(verifyJwt);

router.route('/newContact/:userId').post(userContact)
router.route('/allContacts').get(getAllContacts)
router.route('/:contactId').get(getByIdContact)
router.route('/update/:contactId').put(updateContact)
router.route('/delete/:contactId').delete(deleteContact)

export default router
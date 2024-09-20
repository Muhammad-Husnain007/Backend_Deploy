import { Router } from "express";
import { registerUser, getAllUsers, getByIdUser, loginUser, logoutUser, deleteUser
    , refreshAccessToken
 } from "../controllers/user.controller.js";
import { verifyJwt } from "../middlewares/auth.middleware.js";

const router = Router()

router.route("/refresh-token").post(verifyJwt, refreshAccessToken)
router.route('/register').post(registerUser)
router.route('/').get(getAllUsers)
router.route('/:userId').get(getByIdUser)
router.route('/login').post(loginUser)
router.route('/logout').post(verifyJwt, logoutUser)
router.route('/delete/:userId').post(verifyJwt, deleteUser)

export default router
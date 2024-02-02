import { Router } from "express";
import { authController } from "../controllers/AuthController";

const router: Router = Router();

//Routes
router.post("/auth/sign-in/", authController.signIn);
router.post("/auth/sign-up/", authController.signUp);
router.post("/auth/refresh/", authController.refreshToken);

export { router };

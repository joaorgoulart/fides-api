import { MeetingMinuteController } from "../controllers/meetingMinuteController";
import { AuthController } from "../controllers/authController";
import { UserController } from "../controllers/userController";
import { Router } from "express";

const router = Router();

// Auth
router.post("/login", AuthController.login);

// Meeting Minutes
router.get("/meeting-minutes", MeetingMinuteController.getMeetingMinutes);
router.get("/meeting-minutes/:id", MeetingMinuteController.getMeetingMinuteById);
router.put("/meeting-minutes/:id", MeetingMinuteController.updateMeetingMinute);
router.post("/meeting-minutes/:id/authenticate", MeetingMinuteController.authenticateMeetingMinute);

// User
router.get("/user", UserController.getCurrentUser);

export default router;

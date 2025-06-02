import { MeetingMinuteController } from "../controllers/meetingMinuteController";
import { AuthController } from "../controllers/authController";
import { UserController } from "../controllers/userController";
import { Router } from "express";
import multer from "multer";

const storage = multer.memoryStorage();

const fileFilter = (
    req: any,
    file: Express.Multer.File,
    cb: multer.FileFilterCallback
) => {
    if (file.mimetype === "application/pdf") {
        cb(null, true);
    } else {
        cb(null, false);
    }
};

const upload = multer({ storage: storage, fileFilter: fileFilter });

const router = Router();

// Auth
router.post("/login", AuthController.login);

// Meeting Minutes
router.get("/meeting-minutes", MeetingMinuteController.getMeetingMinutes);
router.get(
    "/meeting-minutes/:id",
    MeetingMinuteController.getMeetingMinuteById
);
router.put("/meeting-minutes/:id", MeetingMinuteController.updateMeetingMinute);
router.post(
    "/meeting-minutes/:id/authenticate",
    MeetingMinuteController.authenticateMeetingMinute
);

// Nova rota para criação de atas (usado pelo kiosk/dispositivo externo)
router.post(
    "/meeting-minutes",
    upload.single("pdf"),
    MeetingMinuteController.createMeetingMinute
);

// User
router.get("/user", UserController.getCurrentUser);

export default router;

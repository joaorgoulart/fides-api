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

router.get("/", (req, res) => {
    res.json({ message: "API online" });
});

// Auth
router.post("/login", AuthController.login);
router.post("/register", AuthController.register);

// Meeting Minutes
router.get("/meeting-minutes", MeetingMinuteController.getMeetingMinutes);
router.get(
    "/meeting-minutes/:id",
    MeetingMinuteController.getMeetingMinuteById
);

// PUT endpoint para atualizar meeting minutes
router.put("/meeting-minutes/:id", MeetingMinuteController.updateMeetingMinute);

// PUT endpoint específico para editar dados LLM
router.put(
    "/meeting-minutes/:id/llm-data",
    MeetingMinuteController.updateLLMData
);

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

// Nova rota para adicionar comentários
router.post(
    "/meeting-minutes/:id/comments",
    MeetingMinuteController.addComment
);

// Nova rota para busca por CNPJ (para mobile app)
router.get(
    "/meeting-minutes/client/:cnpj",
    MeetingMinuteController.getMeetingMinutesByClient
);

router.post(
    "/meeting-minutes/verify",
    upload.single("pdf"),
    MeetingMinuteController.verifyMeetingMinute
);

// User
router.get("/user", UserController.getCurrentUser);
router.put("/user", UserController.updateUser);

// Admin User Management (apenas para usuários NOTARY)
router.get("/admin/users", UserController.getAllUsers);
router.post("/admin/users", UserController.createUser);
router.put("/admin/users/:userId", UserController.updateUserByAdmin);
router.delete("/admin/users/:userId", UserController.deleteUser);

export default router;

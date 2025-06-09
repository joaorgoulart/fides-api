import { MeetingMinuteController } from "../controllers/meetingMinuteController";
import { SignatureController } from "../controllers/signatureController";
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
    // Aceitar PDFs e imagens
    if (file.mimetype === "application/pdf" || 
        file.mimetype.startsWith("image/")) {
        cb(null, true);
    } else {
        const error = new Error(`Tipo de arquivo não suportado: ${file.mimetype}`);
        cb(error as any, false);
    }
};

const upload = multer({ 
    storage: storage, 
    fileFilter: fileFilter,
    limits: {
        fileSize: 50 * 1024 * 1024, // 50MB
        files: 3, // máximo 3 arquivos
        fields: 10 // máximo 10 campos de texto
    }
});

// Instância específica para meeting minutes com configuração mais permissiva
const meetingMinuteUpload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 50 * 1024 * 1024, // 50MB
        files: 5, // mais permissivo
        fields: 20, // mais campos permitidos
        parts: 100 // mais partes permitidas
    }
});

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

// Middleware para tratar erros do multer
const handleMulterError = (err: any, req: any, res: any, next: any) => {
    if (err instanceof multer.MulterError) {
        if (err.message.includes('Unexpected field')) {
            return res.status(400).json({
                success: false,
                error: `Campo inesperado. Campos esperados: pdf, photo, signature. Erro: ${err.message}`
            });
        }
        if (err.message.includes('File too large')) {
            return res.status(400).json({
                success: false,
                error: 'Arquivo muito grande. Tamanho máximo: 50MB'
            });
        }
        return res.status(400).json({
            success: false,
            error: `Erro no upload: ${err.message}`
        });
    }
    next(err);
};

// Nova rota para criação de atas (usado pelo kiosk/dispositivo externo)
router.post(
    "/meeting-minutes",
    meetingMinuteUpload.fields([
        { name: "pdf", maxCount: 1 },
        { name: "photo", maxCount: 1 },
        { name: "signature", maxCount: 1 }
    ]),
    handleMulterError,
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

// Signature
router.get("/signature", SignatureController.getSignature);

export default router;

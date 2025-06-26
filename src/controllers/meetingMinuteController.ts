import {
    requireAuth,
    ApiResponses,
    AuthUser,
    parsePaginationParams,
    requireRole,
    Validators,
} from "../lib/api-utils";
import {
    S3Service,
    LLMService,
    ValidationService,
    FileUtils,
} from "../lib/services";
import prisma, { buildMeetingMinutesFilters } from "../lib/prisma";
import { Request, Response } from "express";
import { BlockchainService } from "../lib/blockchain";
import { AppLogsType } from "../enums/app-log-type";
import { Logger } from "../lib/api-utils";
import crypto from "crypto";

export class MeetingMinuteController {
    static async getMeetingMinutes(req: Request, res: Response): Promise<void> {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            Logger.info("Listando atas", {
                userId: user.userId,
                accessLevel: user.accessLevel,
            });

            // Extrair parâmetros da query string
            const cnpj = (req.query.cnpj as string) || undefined;
            const status = (req.query.status as string) || undefined;
            const dateFrom = (req.query.dateFrom as string) || undefined;
            const dateTo = (req.query.dateTo as string) || undefined;
            const keywords = (req.query.keywords as string) || undefined;
            const page = (req.query.page as string) || undefined;
            const limit = (req.query.limit as string) || undefined;
            const notaryId = (req.query.notaryId as string) || undefined;

            // Construir filtros
            const filters = buildMeetingMinutesFilters({
                cnpj,
                status,
                dateFrom,
                dateTo,
                keywords,
                notaryId,
            });

            // Adicionar filtro por usuário se for CLIENT
            if (user.accessLevel === "CLIENT") {
                filters.userId = user.userId;
            }

            // Parâmetros de paginação
            const pagination = parsePaginationParams(page, limit);

            // Buscar MoMs
            const [moms, total] = await Promise.all([
                prisma.meetingMinute.findMany({
                    where: filters,
                    include: {
                        llmData: {
                            select: {
                                summary: true,
                                keywords: true,
                            },
                        },
                    },
                    orderBy: {
                        createdAt: "desc",
                    },
                    skip: pagination.offset,
                    take: pagination.limit,
                }),
                prisma.meetingMinute.count({ where: filters }),
            ]);

            // Transformar dados para o formato da interface
            const transformedMoms = moms.map((mom: any) => ({
                id: mom.id,
                cnpj: mom.cnpj,
                submissionDate: mom.createdAt.toISOString(),
                status: mom.status.toLowerCase(),
                summary: mom.summary,
                pdfUrl: mom.pdfUrl,
                photoUrl: mom.photoUrl,
                signatureUrl: mom.signatureUrl,
                signaturesValid: mom.signaturesValid,
                blockchainHash: mom.blockchainHash,
                blockchainTxId: mom.blockchainTxId,
                createdBy: mom.user,
                llmData: mom.llmData
                    ? {
                          summary: mom.llmData.summary,
                          keywords: mom.llmData.keywords,
                      }
                    : undefined,
                commentsCount: mom.comments.length,
            }));

            const responseData = {
                meetingMinutes: transformedMoms,
                total,
                page: pagination.page,
                limit: pagination.limit,
                totalPages: Math.ceil(total / pagination.limit),
            };

            Logger.info("Atas listadas com sucesso", {
                count: moms.length,
                total,
                userId: user.userId,
            });

            res.status(200).json(ApiResponses.success(responseData));
        } catch (error) {
            Logger.error("Erro ao listar atas", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async getMeetingMinuteById(
        req: Request,
        res: Response
    ): Promise<void> {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }

            const user = await prisma.user.findUnique({
                where: {
                    id: (authResult as AuthUser).userId,
                },
            });

            const { id } = req.params;

            Logger.info("Buscando ata por ID", {
                momId: id,
                userId: user?.id,
            });

            // Buscar MoM
            const mom = await prisma.meetingMinute.findUnique({
                where: { id },
                include: {
                    llmData: {
                        include: {
                            participants: true,
                        },
                    },
                },
            });

            if (!mom) {
                res.status(404).json(
                    ApiResponses.notFound("Ata não encontrada")
                );
                return;
            }

            // Verificar se o usuário tem acesso (CLIENT só pode ver suas próprias MoMs)
            if (
                user?.accessLevel === "CLIENT" &&
                user.cnpj !== null &&
                mom.cnpj !== user?.cnpj
            ) {
                res.status(403).json(
                    ApiResponses.forbidden("Acesso negado a esta ata")
                );
                return;
            }

            // Transformar dados para o formato da interface
            const transformedMom = {
                id: mom.id,
                cnpj: mom.cnpj,
                submissionDate: mom.createdAt.toISOString(),
                status: mom.status.toLowerCase(),
                summary: mom.summary,
                pdfUrl: mom.pdfUrl,
                photoUrl: mom.photoUrl,
                signatureUrl: mom.signatureUrl,
                blockchainHash: mom.blockchainHash,
                blockchainTxId: mom.blockchainTxId,
                signaturesValid: mom.signaturesValid,
                llmData: mom.llmData
                    ? {
                          summary: mom.llmData.summary,
                          subjects: mom.llmData.subjects,
                          agenda: mom.llmData.agenda,
                          deliberations: mom.llmData.deliberations,
                          participants: mom.llmData.participants,
                          signatures: mom.llmData.signatures,
                          keywords: mom.llmData.keywords,
                      }
                    : undefined,
                comments: mom.comments,
            };

            Logger.info("Ata encontrada", { momId: id, userId: user?.id });

            res.status(200).json(ApiResponses.success(transformedMom));
        } catch (error) {
            Logger.error("Erro ao buscar ata", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async updateMeetingMinute(
        req: Request,
        res: Response
    ): Promise<void> {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            // Verificar autorização (apenas NOTARY podem atualizar)
            if (!requireRole(user, ["NOTARY"])) {
                res.status(403).json(
                    ApiResponses.forbidden(
                        "Apenas cartorários podem atualizar atas"
                    )
                );
                return;
            }

            const { id } = req.params;
            const body = req.body;

            Logger.info("Atualizando ata", { momId: id, userId: user.userId });

            // Verificar se a MoM existe
            const existingMom = await prisma.meetingMinute.findUnique({
                where: { id },
                include: {
                    llmData: true,
                },
            });

            if (!existingMom) {
                res.status(404).json(
                    ApiResponses.notFound("Ata não encontrada")
                );
                return;
            }

            // Campos que podem ser atualizados
            const updateData: any = {};

            if (body.status && Validators.status(body.status)) {
                updateData.status = body.status.toUpperCase();
            }

            if (body.summary) {
                updateData.summary = body.summary;
            }

            if (body.comments && Array.isArray(body.comments)) {
                updateData.comments = body.comments;
            }

            if (body.blockchainHash) {
                updateData.blockchainHash = body.blockchainHash;
            }

            if (body.blockchainTxId) {
                updateData.blockchainTxId = body.blockchainTxId;
            }

            // Atualizar dados do LLM se fornecidos
            if (body.llmData && existingMom.llmData) {
                const llmUpdateData: any = {};

                if (body.llmData.summary)
                    llmUpdateData.summary = body.llmData.summary;
                if (body.llmData.agenda)
                    llmUpdateData.agenda = body.llmData.agenda;
                if (body.llmData.subjects)
                    llmUpdateData.subjects = body.llmData.subjects;
                if (body.llmData.deliberations)
                    llmUpdateData.deliberations = body.llmData.deliberations;
                if (body.llmData.signatures)
                    llmUpdateData.signatures = body.llmData.signatures;
                if (body.llmData.keywords)
                    llmUpdateData.keywords = body.llmData.keywords;

                // Atualizar participantes se fornecidos
                if (
                    body.llmData.participants &&
                    Array.isArray(body.llmData.participants)
                ) {
                    // Primeiro deletar participantes existentes
                    await prisma.participant.deleteMany({
                        where: { llmDataId: existingMom.llmData.id },
                    });

                    // Criar novos participantes
                    await prisma.participant.createMany({
                        data: body.llmData.participants.map((p: any) => ({
                            llmDataId: existingMom.llmData!.id,
                            name: p.name,
                            rg: p.rg,
                            cpf: p.cpf,
                            role: p.role,
                        })),
                    });
                }

                // Atualizar dados do LLM
                if (Object.keys(llmUpdateData).length > 0) {
                    await prisma.lLMData.update({
                        where: { id: existingMom.llmData.id },
                        data: llmUpdateData,
                    });
                }
            }

            // Atualizar MoM
            const updatedMom = await prisma.meetingMinute.update({
                where: { id },
                data: updateData,
                include: {
                    llmData: {
                        include: {
                            participants: true,
                        },
                    },
                },
            });

            const data = {
                userId: user.userId,
                type: AppLogsType.EditDetails,
                info: {
                    momId: id,
                    updateData,
                },
            };
            prisma.appLog.create({ data });
            Logger.info("Ata atualizada com sucesso", {
                momId: id,
                userId: user.userId,
                changes: Object.keys(updateData),
            });

            res.status(200).json(
                ApiResponses.success(updatedMom, "Ata atualizada com sucesso")
            );
        } catch (error) {
            Logger.error("Erro ao atualizar Ata", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async verifyMeetingMinute(
        req: Request,
        res: Response
    ): Promise<void> {
        const pdfFile = req.file;
        if (!pdfFile) {
            res.status(400).json(
                ApiResponses.error("Um arquivo deve ser providenciado")
            );
            return;
        }

        const validateResult = FileUtils.validatePDF(pdfFile.buffer);
        if (!validateResult.isValid) {
            res.status(400).json(
                ApiResponses.error(validateResult.error ?? "")
            );
            return;
        }

        const hash = crypto
            .createHash("sha256")
            .update(pdfFile.buffer)
            .digest("hex");
        const blockchainRes = await BlockchainService.verifyHash(hash);
        res.status(200).json({ result: blockchainRes });
        return;
    }

    static async authenticateMeetingMinute(
        req: Request,
        res: Response
    ): Promise<void> {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            // Verificar autorização (apenas NOTARY podem autenticar)
            if (!requireRole(user, ["NOTARY"])) {
                res.status(403).json(
                    ApiResponses.forbidden(
                        "Apenas cartorários podem autenticar atas"
                    )
                );
                return;
            }

            const { id } = req.params;

            Logger.info("Autenticando ata", { momId: id, userId: user.userId });

            // Verificar se a MoM existe
            const existingMom = await prisma.meetingMinute.findUnique({
                where: { id },
                select: {
                    id: true,
                    status: true,
                    blockchainHash: true,
                    blockchainTxId: true,
                    summary: true,
                    cnpj: true,
                },
            });

            if (!existingMom) {
                res.status(404).json(
                    ApiResponses.notFound("Ata não encontrada")
                );
                return;
            }

            // Verificar se a MoM está em estado válido para autenticação
            if (existingMom.status === "AUTHENTICATED") {
                res.status(400).json(
                    ApiResponses.error("Ata já está autenticada")
                );
                return;
            }

            if (existingMom.status === "REJECTED") {
                res.status(400).json(
                    ApiResponses.error("Ata rejeitada não pode ser autenticada")
                );
                return;
            }

            // Verificar se já possui hash blockchain
            if (existingMom.blockchainHash) {
                res.status(400).json(
                    ApiResponses.error(
                        "Ata já possui hash registrado no blockchain"
                    )
                );
                return;
            }

            const hash = BlockchainService.generateDocumentHash(
                existingMom.summary
            );

            const block = await BlockchainService.submitMomData({
                hash,
                momId: existingMom.id,
                notaryId: "",
                userId: user.userId,
                cnpj: existingMom.cnpj,
            });

            // Atualizar MoM com dados do blockchain
            const authenticatedMom = await prisma.meetingMinute.update({
                where: { id },
                data: {
                    status: "AUTHENTICATED",
                    blockchainHash: block.data.hash,
                    blockchainTxId: block.hash,
                },
                select: {
                    id: true,
                    status: true,
                    blockchainHash: true,
                    blockchainTxId: true,
                },
            });

            res.status(200).json(
                ApiResponses.success(
                    {
                        success: true,
                        blockchainTxId: authenticatedMom.blockchainTxId,
                        blockchainHash: authenticatedMom.blockchainHash,
                    },
                    "Ata autenticada e registrada no blockchain com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro ao autenticar ata", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async createMeetingMinute(
        req: Request,
        res: Response
    ): Promise<void> {
        try {
            // Debug: Logar informações da requisição
            console.log("=== DEBUG createMeetingMinute ===");
            console.log("req.body:", req.body);
            console.log("req.files:", req.files);
            console.log("req.file:", req.file);
            
            if (req.files) {
                console.log("Files object keys:", Object.keys(req.files));
                const files = req.files as { [fieldname: string]: Express.Multer.File[] };
                Object.keys(files).forEach(key => {
                    console.log(`File field '${key}':`, files[key]?.length || 0, "files");
                });
            }
            console.log("=====================================");

            // Extrair dados do formulário
            const { cnpj } = req.body;
            const files = req.files as {
                [fieldname: string]: Express.Multer.File[];
            };

            // Validações básicas
            if (!cnpj) {
                res.status(400).json(ApiResponses.error("CNPJ é obrigatório"));
                return;
            }

            if (!files || !files.pdf || !files.pdf[0]) {
                res.status(400).json(
                    ApiResponses.error("Arquivo PDF é obrigatório")
                );
                return;
            }

            if (!files.photo || !files.photo[0]) {
                res.status(400).json(ApiResponses.error("Foto é obrigatória"));
                return;
            }

            if (!files.signature || !files.signature[0]) {
                res.status(400).json(
                    ApiResponses.error("Assinatura é obrigatória")
                );
                return;
            }

            const pdfFile = files.pdf[0];
            const photoFile = files.photo[0];
            const signatureFile = files.signature[0];

            // Validar arquivo PDF
            const fileValidation = FileUtils.validatePDF(pdfFile.buffer);
            if (!fileValidation.isValid) {
                res.status(400).json(
                    ApiResponses.error(
                        fileValidation.error || "Arquivo PDF inválido"
                    )
                );
                return;
            }

            Logger.info("Validações básicas concluídas", {
                cnpj,
                pdfSize: pdfFile.size,
                pdfName: pdfFile.originalname,
                photoSize: photoFile.size,
                photoName: photoFile.originalname,
                signatureSize: signatureFile.size,
                signatureName: signatureFile.originalname,
            });

            // 1. Upload dos arquivos para S3
            const pdfFileName = FileUtils.generateFileName(
                pdfFile.originalname,
                "ata_"
            );
            const photoFileName = FileUtils.generateFileName(
                photoFile.originalname,
                "foto_"
            );
            const signatureFileName = FileUtils.generateFileName(
                signatureFile.originalname,
                "assinatura_"
            );

            // Upload paralelo dos três arquivos
            const [pdfUrl, photoUrl, signatureUrl] = await Promise.all([
                S3Service.uploadFile(
                    pdfFile.buffer,
                    pdfFileName,
                    pdfFile.mimetype
                ),
                S3Service.uploadFile(
                    photoFile.buffer,
                    photoFileName,
                    photoFile.mimetype
                ),
                S3Service.uploadFile(
                    signatureFile.buffer,
                    signatureFileName,
                    signatureFile.mimetype
                ),
            ]);

            Logger.info("Upload dos arquivos concluído", {
                pdfUrl,
                photoUrl,
                signatureUrl,
            });

            // 2. Validar documento (malware, etc.)
            const docValidation = await ValidationService.validateDocument(
                pdfFile
            );
            if (!docValidation[0]?.document?.validity) {
                // Excluir arquivos se validação falhar
                await Promise.all([
                    S3Service.deleteFile(pdfUrl),
                    S3Service.deleteFile(photoUrl),
                    S3Service.deleteFile(signatureUrl)
                ]);
                res.status(400).json(
                    ApiResponses.error(
                        `Documento inválido: ${JSON.stringify(docValidation)}`
                    )
                );
                return;
            }

            // 3. Criar registro inicial da MoM no banco
            const initialMom = await prisma.meetingMinute.create({
                data: {
                    cnpj,
                    pdfUrl,
                    photoUrl,
                    signatureUrl,
                    signaturesValid: docValidation[0]?.document?.validity,
                    status: "PENDING",
                    summary: "Processando análise do documento...", // Temporário
                },
            });

            Logger.info("Registro inicial da ata criado", {
                momId: initialMom.id,
            });
            // 4. Análise LLM do PDF (processo assíncrono)
            try {
                const llmAnalysis = await LLMService.analyzePDF(pdfUrl);

                // Criar dados LLM no banco
                const llmData = await prisma.lLMData.create({
                    data: {
                        momId: initialMom.id,
                        summary: llmAnalysis.summary,
                        agenda: llmAnalysis.agenda,
                        subjects: llmAnalysis.subjects,
                        deliberations: llmAnalysis.deliberations,
                        signatures: llmAnalysis.signatures,
                        keywords: llmAnalysis.keywords,
                        participants: {
                            create: llmAnalysis.participants.map(
                                (participant: any) => ({
                                    name: participant.name,
                                    rg: participant.rg,
                                    cpf: participant.cpf,
                                    role: participant.role,
                                })
                            ),
                        },
                    },
                });

                // Atualizar MoM com summary da análise LLM
                await prisma.meetingMinute.update({
                    where: { id: initialMom.id },
                    data: {
                        summary: llmAnalysis.summary,
                        signaturesValid: docValidation[0]?.document?.validity,
                        status: "UNDER_REVIEW", // Pronta para revisão do cartorário
                    },
                });

                Logger.info("Análise LLM e validação concluídas", {
                    momId: initialMom.id,
                    participantsCount: llmAnalysis.participants.length,
                });
            } catch (llmError) {
                // Se falhar a análise LLM, manter MoM em PENDING
                Logger.warn("Falha na análise LLM, mantendo ata em PENDING", {
                    momId: initialMom.id,
                    error: llmError,
                });

                await prisma.meetingMinute.update({
                    where: { id: initialMom.id },
                    data: {
                        summary:
                            "Erro na análise automática - revisão manual necessária",
                    },
                });
            }

            // Buscar MoM atualizada para retorno
            const finalMom = await prisma.meetingMinute.findUnique({
                where: { id: initialMom.id },
                include: {
                    llmData: {
                        include: {
                            participants: true,
                        },
                    },
                },
            });

            const responseData = {
                id: finalMom!.id,
                cnpj: finalMom!.cnpj,
                submissionDate: finalMom!.createdAt.toISOString(),
                status: finalMom!.status.toLowerCase(),
                summary: finalMom!.summary,
                pdfUrl: finalMom!.pdfUrl,
                photoUrl: finalMom!.photoUrl,
                signatureUrl: finalMom!.signatureUrl,
                success: true,
            };

            Logger.info("Ata criada com sucesso", {
                momId: finalMom!.id,
                status: finalMom!.status,
                cnpj: finalMom!.cnpj,
            });

            const data = {
                cnpj: finalMom!.cnpj,
                type: AppLogsType.CreateMom,
                info: {
                    ...finalMom,
                },
            };
            prisma.appLog.create({ data });

            res.status(201).json(
                ApiResponses.success(
                    responseData,
                    "Ata submetida com sucesso. Análise LLM e validação iniciadas."
                )
            );
        } catch (error) {
            Logger.error("Erro ao criar ata", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async updateLLMData(req: Request, res: Response): Promise<void> {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            // Verificar autorização (apenas NOTARY podem editar dados LLM)
            if (!requireRole(user, ["NOTARY"])) {
                res.status(403).json(
                    ApiResponses.forbidden(
                        "Apenas cartorários podem editar dados LLM"
                    )
                );
                return;
            }

            const { id } = req.params;
            const { llmData } = req.body;

            Logger.info("Atualizando dados LLM", {
                momId: id,
                userId: user.userId,
            });

            // Verificar se a MoM existe e tem dados LLM
            const existingMom = await prisma.meetingMinute.findUnique({
                where: { id },
                include: {
                    llmData: {
                        include: {
                            participants: true,
                        },
                    },
                },
            });

            if (!existingMom) {
                res.status(404).json(
                    ApiResponses.notFound("Ata não encontrada")
                );
                return;
            }

            if (!existingMom.llmData) {
                res.status(400).json(
                    ApiResponses.error(
                        "Esta ata não possui dados LLM para editar"
                    )
                );
                return;
            }

            // Validar dados de entrada
            if (!llmData) {
                res.status(400).json(
                    ApiResponses.error("Dados LLM são obrigatórios")
                );
                return;
            }

            // Preparar dados para atualização
            const llmUpdateData: any = {};

            if (llmData.summary && typeof llmData.summary === "string") {
                llmUpdateData.summary = llmData.summary.trim();
            }

            if (llmData.agenda && typeof llmData.agenda === "string") {
                llmUpdateData.agenda = llmData.agenda.trim();
            }

            if (llmData.subjects && Array.isArray(llmData.subjects)) {
                llmUpdateData.subjects = llmData.subjects
                    .filter(
                        (subject: any) =>
                            typeof subject === "string" && subject.trim()
                    )
                    .map((subject: string) => subject.trim());
            }

            if (llmData.deliberations && Array.isArray(llmData.deliberations)) {
                llmUpdateData.deliberations = llmData.deliberations
                    .filter(
                        (deliberation: any) =>
                            typeof deliberation === "string" &&
                            deliberation.trim()
                    )
                    .map((deliberation: string) => deliberation.trim());
            }

            if (llmData.signatures && Array.isArray(llmData.signatures)) {
                llmUpdateData.signatures = llmData.signatures
                    .filter(
                        (signature: any) =>
                            typeof signature === "string" && signature.trim()
                    )
                    .map((signature: string) => signature.trim());
            }

            if (llmData.keywords && Array.isArray(llmData.keywords)) {
                llmUpdateData.keywords = llmData.keywords
                    .filter(
                        (keyword: any) =>
                            typeof keyword === "string" && keyword.trim()
                    )
                    .map((keyword: string) => keyword.trim());
            }

            // Atualizar participantes se fornecidos
            if (llmData.participants && Array.isArray(llmData.participants)) {
                // Deletar participantes existentes
                await prisma.participant.deleteMany({
                    where: { llmDataId: existingMom.llmData.id },
                });

                // Criar novos participantes
                await prisma.participant.createMany({
                    data: llmData.participants.map((p: any) => ({
                        llmDataId: existingMom.llmData!.id,
                        name: p.name.trim(),
                        rg: p.rg.trim(),
                        cpf: p.cpf.trim(),
                        role: p.role.trim(),
                    })),
                });
            }

            // Atualizar dados do LLM se houver mudanças
            if (Object.keys(llmUpdateData).length > 0) {
                await prisma.lLMData.update({
                    where: { id: existingMom.llmData.id },
                    data: llmUpdateData,
                });
            }

            // Buscar dados atualizados
            const updatedMom = await prisma.meetingMinute.findUnique({
                where: { id },
                include: {
                    llmData: {
                        include: {
                            participants: true,
                        },
                    },
                },
            });

            // Transformar dados para o formato da interface
            const transformedLLMData = updatedMom?.llmData
                ? {
                      summary: updatedMom.llmData.summary,
                      subjects: updatedMom.llmData.subjects,
                      agenda: updatedMom.llmData.agenda,
                      deliberations: updatedMom.llmData.deliberations,
                      participants: updatedMom.llmData.participants,
                      signatures: updatedMom.llmData.signatures,
                      keywords: updatedMom.llmData.keywords,
                  }
                : null;

            // Log da operação
            const data = {
                userId: user.userId,
                type: AppLogsType.EditLLMData,
                info: {
                    momId: id,
                    updatedFields: Object.keys(llmUpdateData),
                    participantsCount: llmData.participants?.length || 0,
                },
            };
            prisma.appLog.create({ data });

            Logger.info("Dados LLM atualizados com sucesso", {
                momId: id,
                userId: user.userId,
                changes: Object.keys(llmUpdateData),
                participantsCount: llmData.participants?.length || 0,
            });

            res.status(200).json(
                ApiResponses.success(
                    transformedLLMData,
                    "Dados LLM atualizados com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro ao atualizar dados LLM", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async addComment(req: Request, res: Response): Promise<void> {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            // Verificar autorização (apenas NOTARY podem adicionar comentários)
            if (!requireRole(user, ["NOTARY"])) {
                res.status(403).json(
                    ApiResponses.forbidden(
                        "Apenas cartorários podem adicionar comentários"
                    )
                );
                return;
            }

            const { id } = req.params;
            const { comment } = req.body;

            if (
                !comment ||
                typeof comment !== "string" ||
                comment.trim() === ""
            ) {
                res.status(400).json(
                    ApiResponses.error("Comentário é obrigatório")
                );
                return;
            }

            Logger.info("Adicionando comentário à ata", {
                momId: id,
                userId: user.userId,
            });
            // Verificar se a MoM existe
            const existingMom = await prisma.meetingMinute.findUnique({
                where: { id },
                select: { id: true, comments: true },
            });

            if (!existingMom) {
                res.status(404).json(
                    ApiResponses.notFound("Ata não encontrada")
                );
                return;
            }

            // Adicionar comentário à lista existente
            const updatedComments = [...existingMom.comments, comment.trim()];

            // Atualizar MoM com novo comentário
            const updatedMom = await prisma.meetingMinute.update({
                where: { id },
                data: {
                    comments: updatedComments,
                },
                select: {
                    id: true,
                    comments: true,
                },
            });

            Logger.info("Comentário adicionado com sucesso", {
                momId: id,
                userId: user.userId,
                commentsCount: updatedComments.length,
            });

            res.status(200).json(
                ApiResponses.success(
                    {
                        comments: updatedMom.comments,
                        commentsCount: updatedMom.comments.length,
                    },
                    "Comentário adicionado com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro ao adicionar comentário", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async getMeetingMinutesByClient(
        req: Request,
        res: Response
    ): Promise<void> {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            const { cnpj } = req.params;

            Logger.info("Buscando atas por CNPJ", {
                cnpj,
                userId: user.userId,
                accessLevel: user.accessLevel,
            });

            // Verificar se o usuário CLIENT tem acesso ao CNPJ
            if (user.accessLevel === "CLIENT") {
                const userDetails = await prisma.user.findUnique({
                    where: { id: user.userId },
                    select: { cnpj: true },
                });

                if (!userDetails || userDetails.cnpj !== cnpj) {
                    res.status(403).json(
                        ApiResponses.forbidden(
                            "Acesso negado. Você só pode visualizar atas do seu CNPJ"
                        )
                    );
                    return;
                }
            }

            // Parâmetros de paginação
            const page = (req.query.page as string) || undefined;
            const limit = (req.query.limit as string) || undefined;
            const pagination = parsePaginationParams(page, limit);

            // Buscar MoMs por CNPJ
            const [moms, total] = await Promise.all([
                prisma.meetingMinute.findMany({
                    where: { cnpj },
                    select: {
                        id: true,
                        cnpj: true,
                        status: true,
                        summary: true,
                        pdfUrl: true,
                        createdAt: true,
                    },
                    orderBy: {
                        createdAt: "desc",
                    },
                    skip: pagination.offset,
                    take: pagination.limit,
                }),
                prisma.meetingMinute.count({ where: { cnpj } }),
            ]);

            // Transformar dados para o formato da interface
            const transformedMoms = moms.map((mom) => ({
                id: mom.id,
                submissionDate: mom.createdAt.toISOString(),
                status: mom.status.toLowerCase(),
                summary: mom.summary,
                pdfUrl: mom.pdfUrl,
            }));

            const responseData = {
                moms: transformedMoms,
                total,
                page: pagination.page,
                limit: pagination.limit,
                totalPages: Math.ceil(total / pagination.limit),
            };

            Logger.info("Atas encontradas por CNPJ", {
                cnpj,
                count: moms.length,
                total,
                userId: user.userId,
            });

            res.status(200).json(ApiResponses.success(responseData));
        } catch (error) {
            Logger.error("Erro ao buscar atas por CNPJ", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }
}

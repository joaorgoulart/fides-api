import {
    requireAuth,
    ApiResponses,
    AuthUser,
    parsePaginationParams,
    requireRole,
    Validators,
} from "../lib/api-utils";
import prisma, { buildMeetingMinutesFilters } from "../lib/prisma";
import { Request, Response } from "express";
import { Logger } from "../lib/api-utils";

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

            // Construir filtros
            const filters = buildMeetingMinutesFilters({
                cnpj,
                status,
                dateFrom,
                dateTo,
                keywords,
            });

            // Adicionar filtro por usuário se for CLIENT
            if (user.accessLevel === "CLIENT") {
                filters.createdById = user.userId;
            }

            // Parâmetros de paginação
            const pagination = parsePaginationParams(page, limit);

            // Buscar MoMs
            const [moms, total] = await Promise.all([
                prisma.meetingMinute.findMany({
                    where: filters,
                    include: {
                        createdBy: {
                            select: {
                                login: true,
                                name: true,
                            },
                        },
                        updatedBy: {
                            select: {
                                login: true,
                                name: true,
                            },
                        },
                        llmData: {
                            select: {
                                summary: true,
                                keywords: true,
                            },
                        },
                        validationReport: {
                            select: {
                                signaturesValid: true,
                                participantsValid: true,
                                inconsistencies: true,
                            },
                        },
                        _count: {
                            select: {
                                comments: true,
                            },
                        },
                    },
                    orderBy: {
                        submissionDate: "desc",
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
                submissionDate: mom.submissionDate.toISOString(),
                status: mom.status.toLowerCase(),
                summary: mom.summary,
                pdfUrl: mom.pdfUrl,
                photoUrl: mom.photoUrl,
                signatureUrl: mom.signatureUrl,
                blockchainHash: mom.blockchainHash,
                blockchainTxId: mom.blockchainTxId,
                createdBy: mom.createdBy,
                updatedBy: mom.updatedBy,
                llmData: mom.llmData
                    ? {
                          summary: mom.llmData.summary,
                          keywords: mom.llmData.keywords,
                      }
                    : undefined,
                validationReport: mom.validationReport,
                commentsCount: mom._count.comments,
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
            const user = authResult as AuthUser;

            const { id } = req.params;

            Logger.info("Buscando ata por ID", {
                momId: id,
                userId: user.userId,
            });

            // Buscar MoM
            const mom = await prisma.meetingMinute.findUnique({
                where: { id },
                include: {
                    createdBy: {
                        select: {
                            login: true,
                            name: true,
                        },
                    },
                    updatedBy: {
                        select: {
                            login: true,
                            name: true,
                        },
                    },
                    llmData: {
                        include: {
                            participants: true,
                        },
                    },
                    validationReport: true,
                    comments: {
                        include: {
                            author: {
                                select: {
                                    login: true,
                                    name: true,
                                },
                            },
                        },
                        orderBy: {
                            createdAt: "desc",
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
                user.accessLevel === "CLIENT" &&
                mom.createdById !== user.userId
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
                submissionDate: mom.submissionDate.toISOString(),
                status: mom.status.toLowerCase(),
                summary: mom.summary,
                pdfUrl: mom.pdfUrl,
                photoUrl: mom.photoUrl,
                signatureUrl: mom.signatureUrl,
                blockchainHash: mom.blockchainHash,
                blockchainTxId: mom.blockchainTxId,
                createdBy: mom.createdBy,
                updatedBy: mom.updatedBy,
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
                validationReport: mom.validationReport,
                comments: mom.comments.map((comment: any) => comment.content),
            };

            Logger.info("Ata encontrada", { momId: id, userId: user.userId });

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

            // Verificar autorização (apenas NOTARY e ADMIN podem atualizar)
            if (!requireRole(user, ["NOTARY", "ADMIN"])) {
                res.status(403).json(
                    ApiResponses.forbidden(
                        "Apenas cartorários e administradores podem atualizar atas"
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
            });

            if (!existingMom) {
                res.status(404).json(
                    ApiResponses.notFound("Ata não encontrada")
                );
                return;
            }

            // Campos que podem ser atualizados
            const updateData: any = {
                updatedById: user.userId,
            };

            if (body.status && Validators.status(body.status)) {
                updateData.status = body.status.toUpperCase();
            }

            if (body.summary) {
                updateData.summary = body.summary;
            }

            if (body.blockchainHash) {
                updateData.blockchainHash = body.blockchainHash;
            }

            if (body.blockchainTxId) {
                updateData.blockchainTxId = body.blockchainTxId;
            }

            // Atualizar MoM
            const updatedMom = await prisma.meetingMinute.update({
                where: { id },
                data: updateData,
                include: {
                    createdBy: {
                        select: {
                            login: true,
                            name: true,
                        },
                    },
                    updatedBy: {
                        select: {
                            login: true,
                            name: true,
                        },
                    },
                },
            });

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

            // Verificar autorização (apenas NOTARY e ADMIN podem autenticar)
            if (!requireRole(user, ["NOTARY", "ADMIN"])) {
                res.status(403).json(
                    ApiResponses.forbidden(
                        "Apenas cartorários e administradores podem autenticar atas"
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
                    ApiResponses.error("Ata já possui hash registrado no blockchain")
                );
                return;
            }

            // Gerar hash SHA-256 simulado (baseado no ID + timestamp)
            const crypto = require("crypto");
            const hashInput = `${existingMom.id}-${existingMom.summary}-${Date.now()}`;
            const blockchainHash = crypto.createHash("sha256").update(hashInput).digest("hex");
            
            // Simular transação blockchain (será substituído por integração real)
            const blockchainTxId = `tx_${crypto.randomUUID().replace(/-/g, "").substring(0, 16)}`;

            Logger.info("Hash gerado para blockchain", {
                momId: id,
                blockchainHash: blockchainHash.substring(0, 16) + "...",
                blockchainTxId,
            });

            // Atualizar MoM com dados do blockchain
            const authenticatedMom = await prisma.meetingMinute.update({
                where: { id },
                data: {
                    status: "AUTHENTICATED",
                    blockchainHash,
                    blockchainTxId,
                    updatedById: user.userId,
                },
                select: {
                    id: true,
                    status: true,
                    blockchainHash: true,
                    blockchainTxId: true,
                },
            });

            Logger.info("Ata autenticada com sucesso", {
                momId: id,
                userId: user.userId,
                blockchainTxId,
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
}

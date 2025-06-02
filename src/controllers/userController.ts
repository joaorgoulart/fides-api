import { ApiResponses, AuthUser, Logger, requireAuth } from "../lib/api-utils";
import { Request, Response } from "express";
import prisma from "../lib/prisma";

export class UserController {
    static async getCurrentUser(req: Request, res: Response) {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            Logger.info("Buscando perfil do usuário", { userId: user.userId });

            // Buscar dados do usuário
            const userData = await prisma.user.findUnique({
                where: { id: user.userId },
                select: {
                    id: true,
                    login: true,
                    cnpj: true,
                    accessLevel: true,
                    createdAt: true,
                    updatedAt: true,
                    _count: {
                        select: {
                            meetingMinutes: true,
                        },
                    },
                },
            });

            if (!userData) {
                res.status(404).json(
                    ApiResponses.notFound("Usuário não encontrado")
                );
                return;
            }

            // Transformar dados para o formato da interface
            const profile = {
                id: userData.id,
                login: userData.login,
                cnpj: userData.cnpj,
                accessLevel: userData.accessLevel.toLowerCase(),
                createdAt: userData.createdAt.toISOString(),
                updatedAt: userData.updatedAt.toISOString(),
                stats: {
                    createdMoMs: userData._count.meetingMinutes,
                },
            };

            Logger.info("Perfil encontrado", { userId: user.userId });

            res.status(200).json(ApiResponses.success(profile));
        } catch (error) {
            Logger.error("Erro ao buscar perfil", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }
}

import { ApiResponses, AuthUser, Logger, requireAuth, requireRole } from "../lib/api-utils";
import { Request, Response } from "express";
import prisma from "../lib/prisma";
import bcrypt from "bcryptjs";

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
            };

            Logger.info("Perfil encontrado", { userId: user.userId });

            res.status(200).json(ApiResponses.success(profile));
        } catch (error) {
            Logger.error("Erro ao buscar perfil", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async updateUser(req: Request, res: Response) {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            const { currentPassword, newPassword } = req.body;

            // Validações básicas
            if (!currentPassword || !newPassword) {
                res.status(400).json(
                    ApiResponses.error("Senha atual e nova senha são obrigatórias")
                );
                return;
            }

            if (newPassword.length < 6) {
                res.status(400).json(
                    ApiResponses.error("A nova senha deve ter pelo menos 6 caracteres")
                );
                return;
            }

            if (currentPassword === newPassword) {
                res.status(400).json(
                    ApiResponses.error("A nova senha deve ser diferente da senha atual")
                );
                return;
            }

            Logger.info("Atualizando senha do usuário", { userId: user.userId });

            // Buscar usuário atual com senha
            const userData = await prisma.user.findUnique({
                where: { id: user.userId },
                select: {
                    id: true,
                    login: true,
                    password: true,
                },
            });

            if (!userData) {
                res.status(404).json(
                    ApiResponses.notFound("Usuário não encontrado")
                );
                return;
            }

            // Verificar senha atual
            const isCurrentPasswordValid = await bcrypt.compare(
                currentPassword,
                userData.password
            );

            if (!isCurrentPasswordValid) {
                res.status(400).json(
                    ApiResponses.error("Senha atual incorreta")
                );
                return;
            }

            // Hash da nova senha
            const saltRounds = 10;
            const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

            // Atualizar senha no banco de dados
            await prisma.user.update({
                where: { id: user.userId },
                data: {
                    password: hashedNewPassword,
                    updatedAt: new Date(),
                },
            });

            Logger.info("Senha atualizada com sucesso", { userId: user.userId });

            res.status(200).json(
                ApiResponses.success(
                    { message: "Senha atualizada com sucesso" },
                    "Senha atualizada com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro ao atualizar senha", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async createUser(req: Request, res: Response) {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            // Verificar se é admin (NOTARY)
            if (!requireRole(user, ["NOTARY"])) {
                res.status(403).json(
                    ApiResponses.forbidden("Apenas administradores podem criar usuários")
                );
                return;
            }

            const { login, cnpj, password, accessLevel } = req.body;

            // Validações básicas
            if (!login || !password) {
                res.status(400).json(
                    ApiResponses.error("Login e senha são obrigatórios")
                );
                return;
            }

            if (password.length < 6) {
                res.status(400).json(
                    ApiResponses.error("A senha deve ter pelo menos 6 caracteres")
                );
                return;
            }

            // Validar nível de acesso
            if (accessLevel && !["CLIENT", "NOTARY"].includes(accessLevel)) {
                res.status(400).json(
                    ApiResponses.error("Nível de acesso deve ser CLIENT ou NOTARY")
                );
                return;
            }

            // Validar CNPJ se fornecido
            if (cnpj) {
                const cnpjRegex = /^\d{14}$/;
                if (!cnpjRegex.test(cnpj)) {
                    res.status(400).json(
                        ApiResponses.error("CNPJ deve conter exatamente 14 dígitos")
                    );
                    return;
                }
            }

            Logger.info("Admin criando novo usuário", { 
                adminId: user.userId, 
                newUserLogin: login 
            });

            // Verificar se já existe usuário com este login
            const existingUser = await prisma.user.findUnique({
                where: { login },
            });

            if (existingUser) {
                res.status(409).json(
                    ApiResponses.error("Já existe um usuário com este login")
                );
                return;
            }

            // Hash da senha
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Criar usuário no banco
            const newUser = await prisma.user.create({
                data: {
                    login,
                    cnpj: cnpj || null,
                    password: hashedPassword,
                    accessLevel: accessLevel || "CLIENT",
                },
                select: {
                    id: true,
                    login: true,
                    cnpj: true,
                    accessLevel: true,
                    createdAt: true,
                    updatedAt: true,
                },
            });

            Logger.info("Usuário criado com sucesso pelo admin", {
                adminId: user.userId,
                newUserId: newUser.id,
                accessLevel: newUser.accessLevel,
            });

            res.status(201).json(
                ApiResponses.success(
                    {
                        user: newUser,
                        message: "Usuário criado com sucesso",
                    },
                    "Usuário criado com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro ao criar usuário", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async updateUserByAdmin(req: Request, res: Response) {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            // Verificar se é admin (NOTARY)
            if (!requireRole(user, ["NOTARY"])) {
                res.status(403).json(
                    ApiResponses.forbidden("Apenas administradores podem editar usuários")
                );
                return;
            }

            const { userId } = req.params;
            const { login, cnpj, password, accessLevel } = req.body;

            if (!userId) {
                res.status(400).json(
                    ApiResponses.error("ID do usuário é obrigatório")
                );
                return;
            }

            Logger.info("Admin editando usuário", { 
                adminId: user.userId, 
                targetUserId: userId 
            });

            // Verificar se o usuário a ser editado existe
            const existingUser = await prisma.user.findUnique({
                where: { id: userId },
                select: {
                    id: true,
                    login: true,
                    cnpj: true,
                    accessLevel: true,
                },
            });

            if (!existingUser) {
                res.status(404).json(
                    ApiResponses.notFound("Usuário não encontrado")
                );
                return;
            }

            // Preparar dados para atualização
            const updateData: any = {
                updatedAt: new Date(),
            };

            // Validar e atualizar login se fornecido
            if (login !== undefined) {
                if (!login || login.trim() === "") {
                    res.status(400).json(
                        ApiResponses.error("Login não pode estar vazio")
                    );
                    return;
                }

                // Verificar se o novo login já existe (exceto o usuário atual)
                if (login !== existingUser.login) {
                    const loginExists = await prisma.user.findUnique({
                        where: { login },
                    });

                    if (loginExists) {
                        res.status(409).json(
                            ApiResponses.error("Já existe um usuário com este login")
                        );
                        return;
                    }
                }

                updateData.login = login;
            }

            // Validar e atualizar CNPJ se fornecido
            if (cnpj !== undefined) {
                if (cnpj) {
                    const cnpjRegex = /^\d{14}$/;
                    if (!cnpjRegex.test(cnpj)) {
                        res.status(400).json(
                            ApiResponses.error("CNPJ deve conter exatamente 14 dígitos")
                        );
                        return;
                    }
                }
                updateData.cnpj = cnpj || null;
            }

            // Validar e atualizar senha se fornecida
            if (password !== undefined) {
                if (password.length < 6) {
                    res.status(400).json(
                        ApiResponses.error("A senha deve ter pelo menos 6 caracteres")
                    );
                    return;
                }

                const saltRounds = 10;
                updateData.password = await bcrypt.hash(password, saltRounds);
            }

            // Validar e atualizar nível de acesso se fornecido
            if (accessLevel !== undefined) {
                if (!["CLIENT", "NOTARY"].includes(accessLevel)) {
                    res.status(400).json(
                        ApiResponses.error("Nível de acesso deve ser CLIENT ou NOTARY")
                    );
                    return;
                }
                updateData.accessLevel = accessLevel;
            }

            // Atualizar usuário no banco de dados
            const updatedUser = await prisma.user.update({
                where: { id: userId },
                data: updateData,
                select: {
                    id: true,
                    login: true,
                    cnpj: true,
                    accessLevel: true,
                    createdAt: true,
                    updatedAt: true,
                },
            });

            Logger.info("Usuário atualizado com sucesso pelo admin", {
                adminId: user.userId,
                updatedUserId: userId,
                updatedFields: Object.keys(updateData),
            });

            res.status(200).json(
                ApiResponses.success(
                    {
                        user: updatedUser,
                        message: "Usuário atualizado com sucesso",
                    },
                    "Usuário atualizado com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro ao atualizar usuário", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async getAllUsers(req: Request, res: Response) {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            // Verificar se é admin (NOTARY)
            if (!requireRole(user, ["NOTARY"])) {
                res.status(403).json(
                    ApiResponses.forbidden("Apenas administradores podem listar usuários")
                );
                return;
            }

            Logger.info("Admin listando usuários", { adminId: user.userId });

            // Buscar todos os usuários
            const users = await prisma.user.findMany({
                select: {
                    id: true,
                    login: true,
                    cnpj: true,
                    accessLevel: true,
                    createdAt: true,
                    updatedAt: true,
                },
                orderBy: {
                    createdAt: 'desc',
                },
            });

            // Transformar dados para o formato da interface
            const formattedUsers = users.map(userData => ({
                id: userData.id,
                login: userData.login,
                cnpj: userData.cnpj,
                accessLevel: userData.accessLevel.toLowerCase(),
                createdAt: userData.createdAt.toISOString(),
                updatedAt: userData.updatedAt.toISOString(),
            }));

            Logger.info("Lista de usuários retornada", { 
                adminId: user.userId, 
                totalUsers: users.length 
            });

            res.status(200).json(ApiResponses.success(formattedUsers));
        } catch (error) {
            Logger.error("Erro ao listar usuários", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }

    static async deleteUser(req: Request, res: Response) {
        try {
            // Verificar autenticação
            const authResult = requireAuth(req);
            if ("success" in authResult && !authResult.success) {
                res.status(401).json(authResult);
                return;
            }
            const user = authResult as AuthUser;

            // Verificar se é admin (NOTARY)
            if (!requireRole(user, ["NOTARY"])) {
                res.status(403).json(
                    ApiResponses.forbidden("Apenas administradores podem deletar usuários")
                );
                return;
            }

            const { userId } = req.params;

            if (!userId) {
                res.status(400).json(
                    ApiResponses.error("ID do usuário é obrigatório")
                );
                return;
            }

            // Impedir que o admin delete a si mesmo
            if (userId === user.userId) {
                res.status(400).json(
                    ApiResponses.error("Você não pode deletar sua própria conta")
                );
                return;
            }

            Logger.info("Admin deletando usuário", { 
                adminId: user.userId, 
                targetUserId: userId 
            });

            // Verificar se o usuário existe
            const existingUser = await prisma.user.findUnique({
                where: { id: userId },
                select: {
                    id: true,
                    login: true,
                },
            });

            if (!existingUser) {
                res.status(404).json(
                    ApiResponses.notFound("Usuário não encontrado")
                );
                return;
            }


            // Deletar usuário
            await prisma.user.delete({
                where: { id: userId },
            });

            Logger.info("Usuário deletado com sucesso pelo admin", {
                adminId: user.userId,
                deletedUserId: userId,
                deletedLogin: existingUser.login,
            });

            res.status(200).json(
                ApiResponses.success(
                    { message: "Usuário deletado com sucesso" },
                    "Usuário deletado com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro ao deletar usuário", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }
}

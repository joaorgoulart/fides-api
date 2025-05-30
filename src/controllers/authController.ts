import { ApiResponses, Logger } from "../lib/api-utils";
import { Request, Response } from "express";
import prisma from "../lib/prisma";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export class AuthController {
    static async login(req: Request, res: Response): Promise<void> {
        try {
            const { login, password } = req.body;

            // Validação básica
            if (!login || !password) {
                res.status(400).json(
                    ApiResponses.error("Login e senha são obrigatórios")
                );
                return;
            }

            Logger.info("Tentativa de login", { login });

            // Buscar usuário no banco
            const user = await prisma.user.findUnique({
                where: { login },
                select: {
                    id: true,
                    login: true,
                    name: true,
                    email: true,
                    accessLevel: true,
                    password: true,
                },
            });

            if (!user) {
                res.status(401).json(
                    ApiResponses.unauthorized("Credenciais inválidas")
                );
                return;
            }

            // Verificar senha
            const isPasswordValid = await bcrypt.compare(
                password,
                user.password
            );

            if (!isPasswordValid) {
                Logger.warn("Senha inválida", { login });
                res.status(401).json(
                    ApiResponses.unauthorized("Credenciais inválidas")
                );
                return;
            }

            // Gerar JWT
            const token = jwt.sign(
                {
                    userId: user.id,
                    login: user.login,
                    accessLevel: user.accessLevel,
                },
                process.env.JWT_SECRET!,
                { expiresIn: "24h" }
            );

            // Remover senha da resposta
            const { password: _, ...userWithoutPassword } = user;

            Logger.info("Login realizado com sucesso", {
                login,
                accessLevel: user.accessLevel,
            });

            res.status(200).json(
                ApiResponses.success(
                    {
                        token,
                        user: userWithoutPassword,
                        accessLevel: user.accessLevel.toLowerCase(),
                    },
                    "Login realizado com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro no login", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }
}

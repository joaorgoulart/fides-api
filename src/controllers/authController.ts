import { ApiResponses, Logger } from "../lib/api-utils";
import { Request, Response } from "express";
import prisma from "../lib/prisma";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { AppLogsType } from "../enums/app-log-type";

export class AuthController {
    static async login(req: Request, res: Response): Promise<void> {
        try {
            const { login, password } = req.body;

            let data ={
              userId: "",
              type: AppLogsType.LoginFailure,
              info:{
                login,
                reason: "",
              }
            };
            // Validação básica
            if (!login || !password) {
                res.status(400).json(
                    ApiResponses.error("Login e senha são obrigatórios")
                );
                data.info.reason = "Missing Credentials";
                prisma.appLog.create({data});
                return;
            }
            

            Logger.info("Tentativa de login", { login });

            // Buscar usuário no banco
            const user = await prisma.user.findUnique({
                where: { login },
                select: {
                    id: true,
                    login: true,
                    cnpj: true,
                    accessLevel: true,
                    password: true,
                },
            });
                  
            if (!user) {
                res.status(401).json(
                    ApiResponses.unauthorized("Credenciais inválidas")
                );
                data.info.reason = "Invalid Credentials";
                prisma.appLog.create({data});
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
                data.info.reason = "Invalid Password";
                data.userId = user.id;
                prisma.appLog.create({data});
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
            data.type = AppLogsType.LoginSuccess;
            await prisma.appLog.create({data});

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

    static async register(req: Request, res: Response): Promise<void> {
        try {
            const { cnpj, password } = req.body;
            let data = {
              type: AppLogsType.RegisterFailure,
              info: {
                cnpj,
                reason: "",
              }
            };
            // Validação básica
            if (!cnpj || !password) {
                res.status(400).json(
                    ApiResponses.error("CNPJ e senha são obrigatórios")
                );
                data.info.reason = "Missing necessary information";
                prisma.appLog.create({data});
                return;
            }

            // Validação simples do CNPJ (14 dígitos)
            const cnpjRegex = /^\d{14}$/;
            if (!cnpjRegex.test(cnpj)) {
                res.status(400).json(
                    ApiResponses.error("CNPJ deve conter exatamente 14 dígitos")
                );
                data.info.reason = "Invalid CNPJ";
                prisma.appLog.create({data});
                return;
            }

            // Validação básica da senha
            if (password.length < 6) {
                res.status(400).json(
                    ApiResponses.error("Senha deve ter pelo menos 6 caracteres")
                );
                data.info.reason = "Invalid password";
                prisma.appLog.create({data});
                return;
            }

            Logger.info("Tentativa de cadastro", { cnpj });

            // Verificar se já existe usuário com este CNPJ
            const existingUser = await prisma.user.findUnique({
                where: { login: cnpj },
            });

            if (existingUser) {
                res.status(409).json(
                    ApiResponses.error("Já existe uma conta cadastrada com este CNPJ")
                );
                data.info.reason = "User Already Exists";
                prisma.appLog.create({data});
                return;
            }

            // Hash da senha
            const hashedPassword = await bcrypt.hash(password, 10);

            // Criar usuário no banco
            const newUser = await prisma.user.create({
                data: {
                    login: cnpj,
                    cnpj: cnpj,
                    password: hashedPassword,
                    accessLevel: "CLIENT", // Por padrão, novos usuários são clientes
                },
                select: {
                    id: true,
                    login: true,
                    cnpj: true,
                    accessLevel: true,
                },
            });

            Logger.info("Usuário cadastrado com sucesso", {
                cnpj,
                userId: newUser.id,
            });
            data.type = AppLogsType.RegisterSuccess;
            prisma.appLog.create({data});
            res.status(201).json(
                ApiResponses.success(
                    {
                        user: newUser,
                        message: "Conta criada com sucesso. Você já pode fazer login.",
                    },
                    "Cadastro realizado com sucesso"
                )
            );
        } catch (error) {
            Logger.error("Erro no cadastro", error);
            res.status(500).json(ApiResponses.serverError());
        }
    }
}

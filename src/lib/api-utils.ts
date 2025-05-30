import jwt from "jsonwebtoken";
import { Request } from "express";

// Tipos para respostas padronizadas
export interface ApiResponse<T = any> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
}

export interface AuthUser {
    userId: string;
    login: string;
    accessLevel: "CLIENT" | "NOTARY" | "ADMIN";
}

// Respostas padronizadas
export const ApiResponses = {
    success: <T>(data: T, message?: string) => {
        return {
            success: true,
            data,
            message,
        } as ApiResponse<T>;
    },

    error: (message: string, status: number = 400) => {
        return {
            success: false,
            error: message,
        } as ApiResponse;
    },

    unauthorized: (message: string = "Não autorizado") => {
        return {
            success: false,
            error: message,
        } as ApiResponse;
    },

    forbidden: (message: string = "Acesso negado") => {
        return {
            success: false,
            error: message,
        } as ApiResponse;
    },

    notFound: (message: string = "Recurso não encontrado") => {
        return {
            success: false,
            error: message,
        } as ApiResponse;
    },

    serverError: (message: string = "Erro interno do servidor") => {
        return {
            success: false,
            error: message,
        } as ApiResponse;
    },
};

// Validar e extrair usuário do token JWT
export function verifyToken(token: string): AuthUser | null {
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as AuthUser;
        return decoded;
    } catch (error) {
        return null;
    }
}

// Extrair token do header Authorization
export function extractToken(authHeader: string | null): string | null {
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return null;
    }
    return authHeader.substring(7);
}

// Middleware de autenticação
export function requireAuth(request: Request): AuthUser | ApiResponse {
    const authHeader = request.headers.authorization;
    const token = extractToken(authHeader || null);

    if (!token) {
        return ApiResponses.unauthorized("Token de acesso requerido");
    }

    const user = verifyToken(token);
    if (!user) {
        return ApiResponses.unauthorized("Token inválido ou expirado");
    }

    return user;
}

// Middleware de autorização por nível de acesso
export function requireRole(
    user: AuthUser,
    requiredRoles: ("CLIENT" | "NOTARY" | "ADMIN")[]
): boolean {
    return requiredRoles.includes(user.accessLevel);
}

// Validadores comuns
export const Validators = {
    cnpj: (cnpj: string): boolean => {
        return /^\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}$/.test(cnpj);
    },

    dateString: (date: string): boolean => {
        return !isNaN(Date.parse(date));
    },

    uuid: (id: string): boolean => {
        return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
            id
        );
    },

    status: (status: string): boolean => {
        return [
            "pending",
            "under_review",
            "authenticated",
            "rejected",
        ].includes(status);
    },
};

// Utilitário para paginação
export interface PaginationParams {
    page: number;
    limit: number;
    offset: number;
}

export function parsePaginationParams(
    page?: string,
    limit?: string
): PaginationParams {
    const pageNum = Math.max(1, parseInt(page || "1", 10));
    const limitNum = Math.min(50, Math.max(1, parseInt(limit || "10", 10)));
    const offset = (pageNum - 1) * limitNum;

    return {
        page: pageNum,
        limit: limitNum,
        offset,
    };
}

// Utilitário para logging estruturado
export const Logger = {
    info: (message: string, data?: any) => {
        console.log(`[INFO] ${message}`, data || "");
    },

    error: (message: string, error?: any) => {
        console.error(`[ERROR] ${message}`, error || "");
    },

    warn: (message: string, data?: any) => {
        console.warn(`[WARN] ${message}`, data || "");
    },
};

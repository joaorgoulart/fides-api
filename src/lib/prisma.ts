import { PrismaClient } from "../../generated/prisma";

const prismaClientSingleton = () => {
    return new PrismaClient();
};

declare const globalThis: {
    prismaGlobal: ReturnType<typeof prismaClientSingleton>;
} & typeof global;

const prismadb = globalThis.prismaGlobal ?? prismaClientSingleton();

export default prismadb;

if (process.env.NODE_ENV !== "production") globalThis.prismaGlobal = prismadb;

// Utilitários para conversão de tipos
export const mapMeetingMinutesStatus = (status: string) => {
    const statusMap = {
        pending: "PENDING",
        under_review: "UNDER_REVIEW",
        authenticated: "AUTHENTICATED",
        rejected: "REJECTED",
    } as const;

    return statusMap[status as keyof typeof statusMap] || "PENDING";
};

export const mapAccessLevel = (level: string) => {
    const levelMap = {
        client: "CLIENT",
        notary: "NOTARY",
        admin: "ADMIN",
    } as const;

    return levelMap[level as keyof typeof levelMap] || "CLIENT";
};

// Utilitário para buscar MoMs com filtros
export const buildMeetingMinutesFilters = (filters: {
    cnpj?: string;
    dateFrom?: string;
    dateTo?: string;
    status?: string;
    keywords?: string;
}) => {
    const where: any = {};

    if (filters.cnpj) {
        where.cnpj = {
            contains: filters.cnpj,
            mode: "insensitive",
        };
    }

    if (filters.status) {
        where.status = mapMeetingMinutesStatus(filters.status);
    }

    if (filters.dateFrom || filters.dateTo) {
        where.submissionDate = {};
        if (filters.dateFrom) {
            where.submissionDate.gte = new Date(filters.dateFrom);
        }
        if (filters.dateTo) {
            where.submissionDate.lte = new Date(filters.dateTo);
        }
    }

    if (filters.keywords) {
        where.OR = [
            {
                summary: {
                    contains: filters.keywords,
                    mode: "insensitive",
                },
            },
            {
                llmData: {
                    keywords: {
                        hasSome: filters.keywords.split(" "),
                    },
                },
            },
        ];
    }

    return where;
};

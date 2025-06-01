import { PrismaClient } from "../generated/prisma";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
    console.log("🌱 Iniciando seed do banco de dados...");

    // Limpar dados existentes
    await prisma.comment.deleteMany();
    await prisma.validationReport.deleteMany();
    await prisma.participant.deleteMany();
    await prisma.lLMData.deleteMany();
    await prisma.meetingMinute.deleteMany();
    await prisma.user.deleteMany();

    // Criar usuários
    const hashedPassword = await bcrypt.hash("123456", 10);

    const adminUser = await prisma.user.create({
        data: {
            login: "admin",
            email: "admin@fides.com",
            name: "Administrador",
            accessLevel: "ADMIN",
            password: hashedPassword,
        },
    });

    const notaryUser = await prisma.user.create({
        data: {
            login: "cartorario",
            email: "cartorario@fides.com",
            name: "João Silva",
            accessLevel: "NOTARY",
            password: hashedPassword,
        },
    });

    const clientUser = await prisma.user.create({
        data: {
            login: "cliente",
            email: "cliente@empresa.com",
            name: "Maria Santos",
            accessLevel: "CLIENT",
            password: hashedPassword,
        },
    });

    console.log("✅ Usuários criados");

    // Criar MoMs de exemplo
    const mom1 = await prisma.meetingMinute.create({
        data: {
            cnpj: "12345678901234",
            summary:
                "Reunião ordinária do conselho de administração para aprovação do orçamento anual",
            status: "AUTHENTICATED",
            pdfUrl: "http://localhost:3000/sample-ata.pdf",
            photoUrl: "/uploads/mom1-photo.jpg",
            signatureUrl: "/uploads/mom1-signature.jpg",
            blockchainHash: "0x1234567890abcdef",
            blockchainTxId: "tx_1234567890",
            createdById: clientUser.id,
            updatedById: notaryUser.id,
        },
    });

    const mom2 = await prisma.meetingMinute.create({
        data: {
            cnpj: "98765432101234",
            summary:
                "Assembleia geral extraordinária para alteração do estatuto social",
            status: "UNDER_REVIEW",
            pdfUrl: "http://localhost:3000/sample-ata.pdf",
            createdById: clientUser.id,
        },
    });

    const mom3 = await prisma.meetingMinute.create({
        data: {
            cnpj: "1122233344",
            summary: "Reunião de diretoria para aprovação de investimentos",
            status: "PENDING",
            pdfUrl: "http://localhost:3000/sample-ata.pdf",
            createdById: clientUser.id,
        },
    });

    console.log("✅ MoMs criadas");

    // Criar dados LLM para a primeira MoM
    const llmData1 = await prisma.lLMData.create({
        data: {
            momId: mom1.id,
            summary:
                "Reunião do conselho de administração realizada em 15/01/2024 para discussão e aprovação do orçamento anual de 2024.",
            agenda: "Aprovação do orçamento anual 2024; Discussão sobre investimentos; Nomeação de novos diretores",
            subjects: ["Orçamento 2024", "Investimentos", "Nomeações"],
            deliberations: [
                "Aprovado orçamento de R$ 10.000.000 para 2024",
                "Autorizado investimento em nova filial",
                "Nomeado João Silva como diretor financeiro",
            ],
            signatures: [
                "João Silva - Presidente",
                "Maria Santos - Diretora",
                "Pedro Costa - Conselheiro",
            ],
            keywords: ["orçamento", "investimento", "diretoria", "aprovação"],
        },
    });

    // Criar participantes
    await prisma.participant.createMany({
        data: [
            {
                llmDataId: llmData1.id,
                name: "João Silva",
                rg: "12.345.678-9",
                cpf: "123.456.789-00",
                role: "Presidente do Conselho",
            },
            {
                llmDataId: llmData1.id,
                name: "Maria Santos",
                rg: "98.765.432-1",
                cpf: "987.654.321-00",
                role: "Diretora Executiva",
            },
            {
                llmDataId: llmData1.id,
                name: "Pedro Costa",
                rg: "11.222.333-4",
                cpf: "111.222.333-44",
                role: "Conselheiro",
            },
        ],
    });

    console.log("✅ Dados LLM e participantes criados");

    // Criar relatório de validação
    await prisma.validationReport.create({
        data: {
            momId: mom1.id,
            signaturesValid: true,
            participantsValid: true,
            inconsistencies: [],
        },
    });

    await prisma.validationReport.create({
        data: {
            momId: mom2.id,
            signaturesValid: false,
            participantsValid: true,
            inconsistencies: [
                "Assinatura de João Silva não confere com o padrão cadastrado",
            ],
        },
    });

    console.log("✅ Relatórios de validação criados");

    // Criar comentários
    await prisma.comment.createMany({
        data: [
            {
                momId: mom1.id,
                authorId: notaryUser.id,
                content:
                    "Documento validado e autenticado com sucesso. Todas as assinaturas conferem.",
            },
            {
                momId: mom2.id,
                authorId: notaryUser.id,
                content:
                    "Pendente verificação da assinatura do presidente. Solicitado nova documentação.",
            },
            {
                momId: mom3.id,
                authorId: adminUser.id,
                content: "Aguardando análise inicial do documento.",
            },
        ],
    });

    console.log("✅ Comentários criados");

    console.log("🎉 Seed concluído com sucesso!");
    console.log("\n📋 Usuários criados:");
    console.log("- Admin: admin / 123456");
    console.log("- Cartorário: cartorario / 123456");
    console.log("- Cliente: cliente / 123456");
}

main()
    .catch((e) => {
        console.error("❌ Erro durante o seed:", e);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });

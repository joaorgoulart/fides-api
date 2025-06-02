import { PrismaClient } from "../generated/prisma";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
    console.log("🌱 Iniciando seed do banco de dados...");

    // Limpar dados existentes
    await prisma.validationReport.deleteMany();
    await prisma.participant.deleteMany();
    await prisma.lLMData.deleteMany();
    await prisma.meetingMinute.deleteMany();
    await prisma.user.deleteMany();

    // Criar usuários
    const hashedPassword = await bcrypt.hash("123456", 10);

    const notaryUser = await prisma.user.create({
        data: {
            login: "cartorario",
            cnpj: null,
            accessLevel: "NOTARY",
            password: hashedPassword,
        },
    });

    const clientUser = await prisma.user.create({
        data: {
            login: "12345678000190",
            cnpj: "12345678000190",
            accessLevel: "CLIENT",
            password: hashedPassword,
        },
    });

    const clientUser2 = await prisma.user.create({
        data: {
            login: "98765432000110",
            cnpj: "98765432000110",
            accessLevel: "CLIENT",
            password: hashedPassword,
        },
    });

    console.log("✅ Usuários criados");

    // Criar MoMs de exemplo
    const mom1 = await prisma.meetingMinute.create({
        data: {
            cnpj: "12345678000190",
            summary:
                "Reunião ordinária do conselho de administração para aprovação do orçamento anual",
            status: "AUTHENTICATED",
            pdfUrl: "http://localhost:3000/sample-ata.pdf",
            photoUrl: "/uploads/mom1-photo.jpg",
            signatureUrl: "/uploads/mom1-signature.jpg",
            blockchainHash: "0x1234567890abcdef",
            blockchainTxId: "tx_1234567890",
            userId: clientUser.id,
            comments: [
                "Documento validado e autenticado com sucesso. Todas as assinaturas conferem.",
                "Registro blockchain confirmado."
            ],
        },
    });

    const mom2 = await prisma.meetingMinute.create({
        data: {
            cnpj: "98765432000110",
            summary:
                "Assembleia geral extraordinária para alteração do estatuto social",
            status: "UNDER_REVIEW",
            pdfUrl: "http://localhost:3000/sample-ata.pdf",
            userId: clientUser2.id,
            comments: [
                "Pendente verificação da assinatura do presidente. Solicitado nova documentação."
            ],
        },
    });

    const mom3 = await prisma.meetingMinute.create({
        data: {
            cnpj: "12345678000190",
            summary: "Reunião de diretoria para aprovação de investimentos",
            status: "PENDING",
            pdfUrl: "http://localhost:3000/sample-ata.pdf",
            userId: clientUser.id,
            comments: ["Aguardando análise inicial do documento."],
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

    // Criar dados LLM para a segunda MoM
    const llmData2 = await prisma.lLMData.create({
        data: {
            momId: mom2.id,
            summary:
                "Assembleia geral extraordinária realizada em 20/01/2024 para discussão de alterações no estatuto social da empresa.",
            agenda: "Alteração do estatuto social; Aprovação de novas diretrizes; Eleição de novos membros",
            subjects: ["Estatuto Social", "Diretrizes", "Eleições"],
            deliberations: [
                "Aprovada alteração do artigo 5º do estatuto",
                "Aprovadas novas diretrizes de governança",
                "Eleito novo conselho fiscal",
            ],
            signatures: [
                "Ana Costa - Presidente",
                "Carlos Silva - Diretor",
            ],
            keywords: ["estatuto", "assembleia", "alteração", "aprovação"],
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
            {
                llmDataId: llmData2.id,
                name: "Ana Costa",
                rg: "55.666.777-8",
                cpf: "555.666.777-88",
                role: "Presidente",
            },
            {
                llmDataId: llmData2.id,
                name: "Carlos Silva",
                rg: "44.333.222-1",
                cpf: "444.333.222-11",
                role: "Diretor",
            },
        ],
    });

    console.log("✅ Dados LLM e participantes criados");

    // Criar relatórios de validação
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

    await prisma.validationReport.create({
        data: {
            momId: mom3.id,
            signaturesValid: true,
            participantsValid: false,
            inconsistencies: [
                "Documento pendente de análise completa",
            ],
        },
    });

    console.log("✅ Relatórios de validação criados");

    console.log("🎉 Seed concluído com sucesso!");
    console.log("\n📋 Usuários criados:");
    console.log("- Cartorário: cartorario / 123456");
    console.log("- Cliente: cliente / 123456 (CNPJ: 12.345.678/0001-90)");
    console.log("- Empresa 2: empresa2 / 123456 (CNPJ: 98.765.432/0001-10)");
    console.log("\n📄 MoMs criadas:");
    console.log(`- MoM 1: ${mom1.id} (AUTHENTICATED)`);
    console.log(`- MoM 2: ${mom2.id} (UNDER_REVIEW)`);
    console.log(`- MoM 3: ${mom3.id} (PENDING)`);
}

main()
    .catch((e) => {
        console.error("❌ Erro durante o seed:", e);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });

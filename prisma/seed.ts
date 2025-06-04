import { PrismaClient } from "../generated/prisma";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
    console.log("🌱 Iniciando seed do banco de dados...");

    // Limpar dados existentes
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

    console.log("✅ Usuários criados");

    console.log("🎉 Seed concluído com sucesso!");
    console.log("\n📋 Usuários criados:");
    console.log("- Cartorário: cartorario / 123456");
}

main()
    .catch((e) => {
        console.error("❌ Erro durante o seed:", e);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });

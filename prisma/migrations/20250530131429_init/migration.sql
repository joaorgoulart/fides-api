-- CreateEnum
CREATE TYPE "AccessLevel" AS ENUM ('CLIENT', 'NOTARY', 'ADMIN');

-- CreateEnum
CREATE TYPE "MeetingMinutesStatus" AS ENUM ('PENDING', 'UNDER_REVIEW', 'AUTHENTICATED', 'REJECTED');

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "login" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "accessLevel" "AccessLevel" NOT NULL DEFAULT 'CLIENT',
    "password" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "moms" (
    "id" TEXT NOT NULL,
    "cnpj" TEXT NOT NULL,
    "submissionDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" "MeetingMinutesStatus" NOT NULL DEFAULT 'PENDING',
    "summary" TEXT NOT NULL,
    "pdfUrl" TEXT,
    "photoUrl" TEXT,
    "signatureUrl" TEXT,
    "blockchainHash" TEXT,
    "blockchainTxId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdById" TEXT,
    "updatedById" TEXT,

    CONSTRAINT "moms_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "llm_data" (
    "id" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "agenda" TEXT NOT NULL,
    "subjects" TEXT[],
    "deliberations" TEXT[],
    "signatures" TEXT[],
    "keywords" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "momId" TEXT NOT NULL,

    CONSTRAINT "llm_data_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "participants" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "rg" TEXT NOT NULL,
    "cpf" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "llmDataId" TEXT NOT NULL,

    CONSTRAINT "participants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "validation_reports" (
    "id" TEXT NOT NULL,
    "signaturesValid" BOOLEAN NOT NULL DEFAULT false,
    "participantsValid" BOOLEAN NOT NULL DEFAULT false,
    "inconsistencies" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "momId" TEXT NOT NULL,

    CONSTRAINT "validation_reports_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "comments" (
    "id" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "momId" TEXT NOT NULL,
    "authorId" TEXT,

    CONSTRAINT "comments_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_login_key" ON "users"("login");

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "moms_blockchainHash_key" ON "moms"("blockchainHash");

-- CreateIndex
CREATE UNIQUE INDEX "moms_blockchainTxId_key" ON "moms"("blockchainTxId");

-- CreateIndex
CREATE INDEX "moms_cnpj_idx" ON "moms"("cnpj");

-- CreateIndex
CREATE INDEX "moms_status_idx" ON "moms"("status");

-- CreateIndex
CREATE INDEX "moms_submissionDate_idx" ON "moms"("submissionDate");

-- CreateIndex
CREATE INDEX "moms_blockchainHash_idx" ON "moms"("blockchainHash");

-- CreateIndex
CREATE UNIQUE INDEX "llm_data_momId_key" ON "llm_data"("momId");

-- CreateIndex
CREATE INDEX "participants_cpf_idx" ON "participants"("cpf");

-- CreateIndex
CREATE INDEX "participants_rg_idx" ON "participants"("rg");

-- CreateIndex
CREATE UNIQUE INDEX "validation_reports_momId_key" ON "validation_reports"("momId");

-- AddForeignKey
ALTER TABLE "moms" ADD CONSTRAINT "moms_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "moms" ADD CONSTRAINT "moms_updatedById_fkey" FOREIGN KEY ("updatedById") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "llm_data" ADD CONSTRAINT "llm_data_momId_fkey" FOREIGN KEY ("momId") REFERENCES "moms"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "participants" ADD CONSTRAINT "participants_llmDataId_fkey" FOREIGN KEY ("llmDataId") REFERENCES "llm_data"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "validation_reports" ADD CONSTRAINT "validation_reports_momId_fkey" FOREIGN KEY ("momId") REFERENCES "moms"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "comments" ADD CONSTRAINT "comments_momId_fkey" FOREIGN KEY ("momId") REFERENCES "moms"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "comments" ADD CONSTRAINT "comments_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

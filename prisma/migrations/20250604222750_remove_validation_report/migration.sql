/*
  Warnings:

  - You are about to drop the `validation_reports` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "validation_reports" DROP CONSTRAINT "validation_reports_momId_fkey";

-- AlterTable
ALTER TABLE "moms" ADD COLUMN     "inconsistencies" TEXT[],
ADD COLUMN     "signaturesValid" BOOLEAN NOT NULL DEFAULT false;

-- DropTable
DROP TABLE "validation_reports";

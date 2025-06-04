/*
  Warnings:

  - You are about to drop the column `userId` on the `moms` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "moms" DROP CONSTRAINT "moms_userId_fkey";

-- AlterTable
ALTER TABLE "moms" DROP COLUMN "userId";

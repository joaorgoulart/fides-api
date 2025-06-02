/*
  Warnings:

  - The values [ADMIN] on the enum `AccessLevel` will be removed. If these variants are still used in the database, this will fail.
  - You are about to drop the column `createdById` on the `moms` table. All the data in the column will be lost.
  - You are about to drop the column `submissionDate` on the `moms` table. All the data in the column will be lost.
  - You are about to drop the column `updatedById` on the `moms` table. All the data in the column will be lost.
  - You are about to drop the column `email` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `name` on the `users` table. All the data in the column will be lost.
  - You are about to drop the `comments` table. If the table is not empty, all the data it contains will be lost.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "AccessLevel_new" AS ENUM ('CLIENT', 'NOTARY');
ALTER TABLE "users" ALTER COLUMN "accessLevel" DROP DEFAULT;
ALTER TABLE "users" ALTER COLUMN "accessLevel" TYPE "AccessLevel_new" USING ("accessLevel"::text::"AccessLevel_new");
ALTER TYPE "AccessLevel" RENAME TO "AccessLevel_old";
ALTER TYPE "AccessLevel_new" RENAME TO "AccessLevel";
DROP TYPE "AccessLevel_old";
ALTER TABLE "users" ALTER COLUMN "accessLevel" SET DEFAULT 'CLIENT';
COMMIT;

-- DropForeignKey
ALTER TABLE "comments" DROP CONSTRAINT "comments_authorId_fkey";

-- DropForeignKey
ALTER TABLE "comments" DROP CONSTRAINT "comments_momId_fkey";

-- DropForeignKey
ALTER TABLE "moms" DROP CONSTRAINT "moms_createdById_fkey";

-- DropForeignKey
ALTER TABLE "moms" DROP CONSTRAINT "moms_updatedById_fkey";

-- DropIndex
DROP INDEX "moms_submissionDate_idx";

-- DropIndex
DROP INDEX "users_email_key";

-- AlterTable
ALTER TABLE "moms" DROP COLUMN "createdById",
DROP COLUMN "submissionDate",
DROP COLUMN "updatedById",
ADD COLUMN     "comments" TEXT[],
ADD COLUMN     "userId" TEXT;

-- AlterTable
ALTER TABLE "users" DROP COLUMN "email",
DROP COLUMN "name",
ADD COLUMN     "cnpj" TEXT;

-- DropTable
DROP TABLE "comments";

-- AddForeignKey
ALTER TABLE "moms" ADD CONSTRAINT "moms_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

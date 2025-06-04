-- AlterTable
ALTER TABLE "moms" ADD COLUMN     "notaryId" TEXT;

-- CreateTable
CREATE TABLE "app_logs" (
    "id" UUID NOT NULL,
    "type" TEXT,
    "user_id" TEXT,
    "info" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "app_logs_pkey" PRIMARY KEY ("id")
);

import { Request, Response } from "express";
import { ApiResponses } from "../lib/api-utils";
import prisma from "../lib/prisma";
import { FileUtils, S3Service } from "../lib/services";

export class SignatureController {
    static async getSignature(req: Request, res: Response) {
        const { cpf } = req.body;
        const signature = await prisma.signature.findFirst({
            where: {
                cpf: cpf,
            },
        });
        res.status(200).json(
            ApiResponses.success(signature, "Signature found")
        );
    }

    static async createSignature(req: Request, res: Response) {
        const { cpf } = req.body;
        const signatureFile = req.file;

        if (!signatureFile) {
            res.status(400).json(ApiResponses.error("PDF file is required"));
            return;
        }

        const signatureFileName = FileUtils.generateFileName(
            signatureFile.originalname,
            "assinatura_"
        );

        const signatureUrl = await S3Service.uploadFile(
            signatureFile.buffer,
            signatureFileName,
            signatureFile.mimetype
        );

        const newSignature = await prisma.signature.create({
            data: { cpf, url: signatureUrl },
        });
        res.status(201).json(
            ApiResponses.success(newSignature, "Signature created")
        );
    }
}

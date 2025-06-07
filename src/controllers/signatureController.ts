import { Request, Response } from "express";
import { ApiResponses } from "../lib/api-utils";
import prisma from "../lib/prisma";

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
}

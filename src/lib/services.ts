import { OpenAI } from "openai";
import crypto from "crypto";
import {
    GetObjectCommand,
    PutObjectCommand,
    S3Client,
} from "@aws-sdk/client-s3";
import axios from "axios";
import FormData, { Readable } from "form-data";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

// Interfaces para tipos de dados
export interface LLMAnalysisResponse {
    summary: string;
    subjects: string[];
    agenda: string;
    deliberations: string[];
    participants: Array<{
        name: string;
        rg: string;
        cpf: string;
        role: string;
    }>;
    signatures: string[];
    keywords: string[];
}

export interface BlockchainResponse {
    success: boolean;
    blockchainTxId: string;
    hash: string;
}

// Serviços simulados para integração com AWS S3
export class S3Service {
    static async uploadFile(
        file: Buffer,
        fileName: string,
        contentType: string
    ): Promise<string> {
        const s3 = new S3Client({
            region: "us-east-2",
            credentials: {
                accessKeyId: process.env.AWS_ACCESS_KEY_ID || "",
                secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "",
            },
        });

        const params = {
            Bucket: process.env.AWS_BUCKET_NAME || "",
            Key: fileName,
            Body: file,
            ContentType: contentType,
        };

        await s3.send(new PutObjectCommand(params));

        const command = new GetObjectCommand({
            Bucket: process.env.AWS_BUCKET_NAME || "", // Specify the AWS S3 bucket name
            Key: fileName, // Specify the file name
        });

        const url = await getSignedUrl(s3, command, {
            expiresIn: 3600,
        });

        return url;
    }

    static async getPdfFromS3(bucket: string, key: string): Promise<Buffer> {
        const s3 = new S3Client({
            region: "us-east-2",
            credentials: {
                accessKeyId: process.env.AWS_ACCESS_KEY_ID || "",
                secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "",
            },
        });
        const command = new GetObjectCommand({ Bucket: bucket, Key: key });
        const response = await s3.send(command);
        if (!response.Body) {
            throw new Error("Erro ao obter o PDF");
        }

        // Converter stream para Buffer
        const chunks: Buffer[] = [];
        const stream = response.Body as any;
        for await (const chunk of stream) {
            chunks.push(chunk);
        }
        return Buffer.concat(chunks);
    }

    static async deleteFile(fileUrl: string): Promise<void> {
        console.log(`🗑️ Simulando exclusão de arquivo: ${fileUrl}`);
        await new Promise((resolve) => setTimeout(resolve, 500));
    }

    static getFileNameFromUrl(url: string): string {
        const path = new URL(url).pathname; // pega o caminho, ex: "/ata_1749071328620_fd1a34c3.pdf"
        return path.substring(path.lastIndexOf("/") + 1); // extrai só o nome do arquivo
    }
}

// Serviço para integração com LLM
export class LLMService {
    static async analyzePDF(pdfUrl: string): Promise<LLMAnalysisResponse> {
        try {
            // Dados simulados baseados na análise
            console.log(`🤖 Analisando PDF com LLM: ${pdfUrl}`);

            const fileName = S3Service.getFileNameFromUrl(pdfUrl);

            const pdf = await S3Service.getPdfFromS3(
                process.env.AWS_BUCKET_NAME || "",
                fileName
            );

            const apiKey = process.env.OPENAI_API_KEY;
            const model = "gpt-4.1-nano";

            const client = new OpenAI({ apiKey });

            const file = await client.files.create({
                file: new File([pdf], fileName, { type: "application/pdf" }),
                purpose: "assistants", // ou 'fine-tune', dependendo do uso
            });

            const response = await client.chat.completions.create({
                model: model,
                messages: [
                    {
                        role: "system",
                        content:
                            "Extract the main subjects, agenda, deliberations, signatures, keywords, participants and inconsistencies, in portuguese (pt-BR) from the following pdf file: ",
                    },
                    {
                        role: "user",
                        content: [
                            {
                                type: "file",
                                file: {
                                    file_id: file.id,
                                },
                            },
                            {
                                type: "text",
                                text: "Extract the main subjects, agenda, deliberations, signatures, keywords, participants and inconsistencies, in portuguese (pt-BR) from the following pdf file: ",
                            },
                        ],
                    },
                ],
                response_format: {
                    type: "json_schema",
                    json_schema: {
                        name: "LLMAnalysisResponse",
                        strict: true,
                        schema: {
                            type: "object",
                            properties: {
                                summary: { type: "string" },
                                inconsistencies: {
                                    type: "array",
                                    items: { type: "string" },
                                },
                                subjects: {
                                    type: "array",
                                    items: { type: "string" },
                                },
                                agenda: { type: "string" },
                                deliberations: {
                                    type: "array",
                                    items: { type: "string" },
                                },
                                participants: {
                                    type: "array",
                                    items: {
                                        type: "object",
                                        properties: {
                                            name: { type: "string" },
                                            rg: { type: "string" },
                                            cpf: { type: "string" },
                                            role: { type: "string" },
                                        },
                                        required: ["name", "rg", "cpf", "role"],
                                        additionalProperties: false,
                                    },
                                },
                                signatures: {
                                    type: "array",
                                    items: { type: "string" },
                                },
                                keywords: {
                                    type: "array",
                                    items: { type: "string" },
                                },
                            },
                            required: [
                                "summary",
                                "subjects",
                                "agenda",
                                "deliberations",
                                "inconsistencies",
                                "participants",
                                "signatures",
                                "keywords",
                            ],
                            additionalProperties: false,
                        },
                    },
                },
                temperature: 1,
                top_p: 1,
            });

            console.log(
                `✅ Análise LLM concluída. Encontrados ${response.choices[0].message.content} participantes.`
            );
            return JSON.parse(response.choices[0].message.content || "{}");
        } catch (error) {
            console.error("❌ Erro na análise LLM:", error);
            throw new Error("Falha na análise do documento pelo LLM");
        }
    }
}

// Serviço para validação de assinaturas e participantes
export class ValidationService {
    static async validateDocument(file: Express.Multer.File): Promise<any> {
        // Create a FormData instance
        const form = new FormData();

        // Append the file to the form data
        form.append("signature_files[]", file.buffer, {
            filename: file.originalname,
            contentType: file.mimetype,
        });

        try {
            // Send POST request to the VALIDAR API
            const response = await axios.post(
                "https://validar.iti.gov.br/arquivo",
                form,
                {
                    headers: {
                        ...form.getHeaders(),
                        Origin: "https://validar.iti.gov.br",
                        Referer: "https://validar.iti.gov.br/",
                    },
                    maxContentLength: Infinity,
                    maxBodyLength: Infinity,
                }
            );

            // Return the response data
            return response.data;
        } catch (error: any) {
            // Handle errors
            if (error.response) {
                // Server responded with a status code outside 2xx
                throw new Error(
                    `VALIDAR API error: ${error.response.status} - ${error.response.data}`
                );
            } else if (error.request) {
                // No response received
                throw new Error("No response received from VALIDAR API.");
            } else {
                // Other errors
                throw new Error(
                    `Error sending request to VALIDAR API: ${error.message}`
                );
            }
        }
    }
}

// Utilitários para validação de arquivos
export class FileUtils {
    static validatePDF(buffer: Buffer): { isValid: boolean; error?: string } {
        // Verificar assinatura PDF
        const pdfHeader = buffer.toString("ascii", 0, 4);
        if (pdfHeader !== "%PDF") {
            return { isValid: false, error: "Arquivo não é um PDF válido" };
        }

        // Verificar tamanho (máximo 10MB conforme PRD)
        const maxSize = 10 * 1024 * 1024; // 10MB
        if (buffer.length > maxSize) {
            return {
                isValid: false,
                error: "Arquivo excede o tamanho máximo de 10MB",
            };
        }

        return { isValid: true };
    }

    static generateFileName(originalName: string, prefix: string = ""): string {
        const timestamp = Date.now();
        const random = crypto.randomBytes(4).toString("hex");
        const extension = originalName.split(".").pop();
        return `${prefix}${timestamp}_${random}.${extension}`;
    }
}

import { OpenAI } from "openai";
import crypto from "crypto";
import axios from "axios";  
import FormData from "form-data";
import { unlink , writeFile} from "fs/promises";
import { promisify } from "util";
import { execFile } from "child_process"; 
import { Blob } from "buffer";
import {
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

// Polyfill para File no Node.js se não estiver disponível
if (typeof globalThis.File === 'undefined') {
  globalThis.File = class extends Blob {
    name: string;
    lastModified: number;

    constructor(fileBits: any[], fileName: string, options?: { type?: string; lastModified?: number }) {
      super(fileBits, options);
      this.name = fileName;
      this.lastModified = options?.lastModified ?? Date.now();
    }
  } as any;
}

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
const execFileAsync = promisify(execFile);

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

        // Retornar URL pública permanente
        const bucketName = process.env.AWS_BUCKET_NAME || "";
        const region = "us-east-2";
        const publicUrl = `https://${bucketName}.s3.${region}.amazonaws.com/${fileName}`;

        return publicUrl;
    }

    // Função para gerar URL assinada de longo prazo (opcional)
    static async generateSignedUrl(fileName: string, expiresInDays: number = 365): Promise<string> {
        const s3 = new S3Client({
            region: "us-east-2",
            credentials: {
                accessKeyId: process.env.AWS_ACCESS_KEY_ID || "",
                secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "",
            },
        });

        const command = new GetObjectCommand({
            Bucket: process.env.AWS_BUCKET_NAME || "",
            Key: fileName,
        });

        const url = await getSignedUrl(s3, command, {
            expiresIn: expiresInDays * 24 * 60 * 60, // Converter dias para segundos
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

            // Usar o File constructor que agora está disponível
            const file = await client.files.create({
                file: new File([pdf], fileName, { type: "application/pdf" }),
                purpose: "assistants",
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
            const extractedSigs = await this.extractDigitalSignatures(file);
            if(extractedSigs?.length){
              return{
                signatures: extractedSigs,
                isValid: extractedSigs.every((s) => s.validity)
              }
            }
            // Handle errors
            if (error.response) {
                // Server responded with a status code outside 2xx
                throw new Error(
                    `VALIDAR API error: ${error.response.status} - ${JSON.stringify(error.response.data)}`
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

  static async extractDigitalSignatures(file: Express.Multer.File){
    try{
      const tempPath = `/tmp/upload-${crypto.randomUUID()}.pdf`;
      await writeFile(tempPath, file.buffer);

      const { stdout } = await execFileAsync('pdfsig', [tempPath]);
      unlink(tempPath);

      return this.parsePdfSigOutput(stdout);
    } catch (error) {
      console.error('Error extracting signatures:', error);
      return null;
    }
  }

  static parsePdfSigOutput(output: string) {
    const lines = output.split('\n');
    const sigs: any[] = [];
    let current: any = {};

    for (const line of lines) {
      const trimmed = line.trim().toLowerCase();
      if (trimmed.includes("signature #")) {
        if (Object.keys(current).length > 0) sigs.push(current);
        current = {};
      } else {
        const [key, rest] = trimmed.split(':', 2);
        if (key && rest?.length) {
          const parsedKey = this.parsePdfSigKey(key);
          const parsedSigValue = this.parsePdfSigValue(parsedKey, rest);
          current[parsedKey] = parsedSigValue;
        }
      }
    }

    if (Object.keys(current).length > 0) sigs.push(current);

    return sigs;
  }

  static parsePdfSigKey(rawKey: string): string{
    const lwKey = rawKey.toLowerCase();
    if(lwKey.includes("field name"))
      return "name";
    if(lwKey.includes("certificate common name"))
      return "ccn";
    if(lwKey.includes("distinguished name"))
      return "distinguishedName";
    if(lwKey.includes("time"))
      return "timestamp";
    if(lwKey.includes("hash algorithm"))
      return "hashAlgo";
    if(lwKey.includes("type"))
      return "type";
    if(lwKey.includes("ranges"))
      return "ranges";
    if(lwKey.includes("signature validation"))
      return "validity";
    if(lwKey.includes("certificate validation"))
      return "issuer";
    if(lwKey.includes("total document signed"))
      return "total";
    return "unknown";
  }

  static parsePdfSigValue(key: string, rawValue: string){
    switch(key){
      case "validity":
        return rawValue.toLowerCase().includes("is valid");
      case "timestamp":
        return new Date(rawValue.trim()) || rawValue.trim();
      case "ranges":
        return this.parsePdfSigKeyRanges(rawValue) ?? [];
      default:
        return rawValue.trim();
    }
  }

  static parsePdfSigKeyRanges(ranges: string): [number, number][]{
    // Remove unnecessary whitespace and newlines
    const cleaned = ranges.replace(/\s+/g, ' ').trim();

    // Match all ranges like [0 - 606577]
    const regex = /\[(\d+)\s*-\s*(\d+)\]/g;

    const result: [number, number][] = [];
    let match: RegExpExecArray | null;

    while ((match = regex.exec(cleaned)) !== null) {
      const start = parseInt(match[1], 10);
      const end = parseInt(match[2], 10);
      result.push([start, end]);
    }

    return result;
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

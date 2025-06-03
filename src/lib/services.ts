import { OpenAI } from "openai";
import crypto from "crypto";
import AWS from "aws-sdk";
import axios from "axios";  

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
        const s3 = new AWS.S3({
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        });

        const params = {
            Bucket: process.env.AWS_BUCKET_NAME || "",
            Key: fileName,
            Body: file,
            ContentType: contentType,
        };

        const result = await s3.upload(params).promise();

        return result.Location;
    }

    static async deleteFile(fileUrl: string): Promise<void> {
        console.log(`🗑️ Simulando exclusão de arquivo: ${fileUrl}`);
        await new Promise((resolve) => setTimeout(resolve, 500));
    }
}

// Serviço para integração com LLM
export class LLMService {
    static async analyzePDF(pdfUrl: string): Promise<LLMAnalysisResponse> {
        try {
            // Dados simulados baseados na análise
            console.log(`🤖 Analisando PDF com LLM: ${pdfUrl}`);
    
            const token = process.env.GITHUB_AI_TOKEN;
            const endpoint = "https://models.github.ai/inference";
            const model = "openai/gpt-4.1";
    
            const client = new OpenAI({ baseURL: endpoint, apiKey: token });
    
            const response = await client.chat.completions.create({
                messages: [
                    {
                        role: "system",
                        content:
                            "Extract the main subjects, agenda, deliberations, signatures, keywords and participants, in portuguese (pt-BR) from the following text, response : ",
                    },
                    { role: "user", content: pdfUrl },
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
                                    items: { type: "object" },
                                },
                            },
                        },
                    },
                },
                temperature: 1,
                top_p: 1,
                model: model,
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
    static async validateDocument(
        pdfUrl: string
    ): Promise<{ isValid: boolean; errors: string[] }> {
        console.log(`📄 Validando documento PDF: ${pdfUrl}`);

        // Simulação de validação de malware e formato
        await new Promise((resolve) => setTimeout(resolve, 1000));

        return {
            isValid: true,
            errors: [],
        };
    }
}

export interface UploadToBlockchainParams{
  hash: string;
  momId: string;
  notaryId: string;
  userId: string;
  cnpj: string;
}

// Serviço para integração com blockchain
export class BlockchainService {
    static async submitMomData(params: UploadToBlockchainParams): Promise<BlockchainResponse> {
        try {
            const blockchainUrl = "";
            const config ={
              headers: {
                'x-api-key': ""
              } 
            };
            const res = await axios.post(blockchainUrl, params, config);
            return res.data;
        } catch (error) {
            console.error("❌ Erro ao submeter hash para blockchain:", error);
            throw new Error("Falha no registro blockchain");
        }
    }

    static async verifyHash(hash: string): Promise<boolean>{
        try {
            const blockchainUrl = "";
            const config ={
              headers: {
                'x-api-key': ""
              },
              params:{
                hash,
              }
            };
            const res = await axios.get(blockchainUrl, config);
            return res.data;
        } catch (error) {
            console.error("❌ Erro ao verificar existencia hash na blockchain:", error);
            throw new Error("Falha ao verificar hash") 
        }
    }


    static generateDocumentHash(content: string): string {
        return crypto.createHash("sha256").update(content).digest("hex");
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

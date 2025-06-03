import axios from "axios"
import crypto from "crypto"

export interface UploadToBlockchainParams{
  hash: string;
  momId: string;
  notaryId: string;
  userId: string;
  cnpj: string;
}

export interface Block{
  hash: string;
  prevHash: string;
  nonce: number;
  timestamp: number;
  data: BlockData;
}

export interface BlockData{
  hash: string;
  momId: string;
  notaryId: string;
  userId: string;
  cnpj: string;
}

export class BlockchainService {
    static async submitMomData(params: UploadToBlockchainParams): Promise<Block> {
        try {
            const blockchainUrl = "";
            const config ={
              headers: {
                'x-api-key': "" //load from .env
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
                'x-api-key': "" //load from .env
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

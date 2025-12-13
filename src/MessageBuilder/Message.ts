
import * as PrismUtil from "@/Util";
import EncryptedMessage from "@/MessageBuilder/EncryptedMessage"
import { SymmetricEncryption } from "@/types";

export default class Message {

  public readonly data: Uint8Array

  constructor(data: Uint8Array | string | object) {
    if (data instanceof Uint8Array) {
      this.data = data;
    } else if (typeof data === "string") {
      this.data = new TextEncoder().encode(data);
    } else if (data && typeof data === "object") {
      this.data = new TextEncoder().encode(JSON.stringify(data));
    } else {
      throw new TypeError("Unsupported input type");
    }
  }

  public strDecode(): string {
    return new TextDecoder().decode(this.data);
  }

  public objDecode(): object {
    return JSON.parse(this.strDecode());
  }

  public serialize(): Uint8Array {
    return this.data
  }

  public static deserialize(serializedMessage: Uint8Array): Message {
    return new Message(serializedMessage);
  }

  public async encrypt(type: string = "", sessionStreamTx: Uint8Array | undefined = undefined, count: number = 0): Promise<EncryptedMessage> {
    const encodedData: Uint8Array = this.serialize();

    if (sessionStreamTx) {
      const countB: Uint8Array = new TextEncoder().encode(count.toString());
      let symmetricEncrypt: SymmetricEncryption = await PrismUtil.symmetricEncrypt(encodedData, sessionStreamTx, countB);
      return new EncryptedMessage(symmetricEncrypt.cipher, symmetricEncrypt.nonce, count, type);
    }

    return new EncryptedMessage(encodedData, new Uint8Array(0), count, type);
  }

}


import * as PrismUtil from "@/Util";
import EncryptedMessage from "@/MessageBuilder/EncryptedMessage"
import type { SymmetricEncryption } from "@/types";

export default class Message {

  public data: Uint8Array;

  constructor() {
    this.data = new Uint8Array(0);
  }

  public static async create(data: Uint8Array | string | object): Promise<Message> {
    const message = new Message();

    if (data instanceof Uint8Array) {
      message.data = data;
    } else if (typeof data === "string") {
      message.data = await PrismUtil.fromString(data);
    } else if (data && typeof data === "object") {
      message.data = await PrismUtil.fromString(JSON.stringify(data));
    } else {
      throw new TypeError("Unsupported input type");
    }

    return message;
  }

  public async strDecode(): Promise<string> {
    return await PrismUtil.toString(this.data);
  }

  public async objDecode(): Promise<object> {
    return JSON.parse(await this.strDecode());
  }

  public serialize(): Uint8Array {
    return this.data
  }

  public static async deserialize(serializedMessage: Uint8Array): Promise<Message> {
    return await Message.create(serializedMessage);
  }

  public async encrypt(type: string = "", sessionStreamTx: Uint8Array | undefined = undefined, count: number = 0): Promise<EncryptedMessage> {
    const encodedData: Uint8Array = this.serialize();

    if (sessionStreamTx) {
      const countB: Uint8Array = await PrismUtil.fromString(count.toString());
      let symmetricEncrypt: SymmetricEncryption = await PrismUtil.symmetricEncrypt(encodedData, sessionStreamTx, undefined, countB);
      return new EncryptedMessage(symmetricEncrypt.cipher, symmetricEncrypt.nonce, count, type);
    }

    return new EncryptedMessage(encodedData, new Uint8Array(0), count, type);
  }

}


import * as PrismUtil from "@/Util";
import Message from "@/MessageBuilder/Message";
import Package from "@/MessageBuilder/Package";

export default class EncryptedMessage {

  public readonly data: Uint8Array;
  public readonly nonce: Uint8Array;
  public readonly count: number;

  public type: string;
  public timestamp: number;

  constructor(
    data: Uint8Array,
    nonce: Uint8Array,
    count: number,
    type: string,
    timestamp: number = Date.now()
  ) {
    this.data = data;
    this.nonce = nonce;
    this.count = count;
    this.type = type;
    this.timestamp = timestamp;
  }

  public serialize(): Uint8Array {
    this.timestamp = Date.now();
    return PrismUtil.Uint8ArrayPack([
      this.data,
      this.nonce,
      new TextEncoder().encode(this.count.toString()),
      new TextEncoder().encode(this.type),
      new TextEncoder().encode(this.timestamp.toString()),
    ]);
  }

  public static deserialize(serializedEncryptedMessage: Uint8Array): EncryptedMessage {
    const unpacked: Uint8Array[] = PrismUtil.Uint8ArrayUnpack(serializedEncryptedMessage);
    return new EncryptedMessage(
      unpacked[0],
      unpacked[1],
      Number(new TextDecoder().decode(unpacked[2])),
      new TextDecoder().decode(unpacked[3]),
      Number(new TextDecoder().decode(unpacked[4])),
    );
  }

  public async decrypt(sessionStreamRx: Uint8Array | undefined = undefined): Promise<Message> {
    if (sessionStreamRx !== undefined) {
      const decrypted: Uint8Array = await PrismUtil.symmetricDecrypt(
        this.data,
        sessionStreamRx,
        this.nonce,
        new TextEncoder().encode(this.count.toString())
      );
      return Message.deserialize(decrypted);
    }

    return Message.deserialize(this.data);
  }

  public async pack(senderIpk: Uint8Array, senderIsk: Uint8Array): Promise<Package> {
    this.timestamp = Date.now();
    const serialized = this.serialize();
    const signature: Uint8Array = await PrismUtil.sign(serialized, senderIsk);
    return new Package(serialized, signature, senderIpk);
  }

}


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

  public async serialize(): Promise<Uint8Array> {
    this.timestamp = Date.now();
    return PrismUtil.pack([
      this.data,
      this.nonce,
      await PrismUtil.fromString(this.count.toString()),
      await PrismUtil.fromString(this.type),
      await PrismUtil.fromString(this.timestamp.toString())
    ]);
  }

  public static async deserialize(serializedEncryptedMessage: Uint8Array): Promise<EncryptedMessage> {
    const unpacked: Uint8Array[] = PrismUtil.unpack(serializedEncryptedMessage);
    return new EncryptedMessage(
      unpacked[0],
      unpacked[1],
      Number(await PrismUtil.toString(unpacked[2])),
      await PrismUtil.toString(unpacked[3]),
      Number(await PrismUtil.toString(unpacked[4])),
    );
  }

  public async decrypt(sessionStreamRx: Uint8Array | undefined = undefined): Promise<Message> {
    if (sessionStreamRx !== undefined) {
      const decrypted: Uint8Array = await PrismUtil.symmetricDecrypt(
        this.data,
        sessionStreamRx,
        this.nonce,
        await PrismUtil.fromString(this.count.toString())
      );
      return await Message.deserialize(decrypted);
    }

    return await Message.deserialize(this.data);
  }

  public async pack(senderIpk: Uint8Array, senderIsk: Uint8Array): Promise<Package> {
    this.timestamp = Date.now();
    const serialized = await this.serialize();
    const signature: Uint8Array = await PrismUtil.sign(serialized, senderIsk);
    return new Package(serialized, signature, senderIpk);
  }

}

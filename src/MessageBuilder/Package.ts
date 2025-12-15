
import * as PrismUtil from "@/Util";
import EncryptedMessage from "@/MessageBuilder/EncryptedMessage"
import SealedPackage from "@/MessageBuilder/SealedPackage";

export default class Package {

  public readonly data: Uint8Array;
  public readonly signature: Uint8Array;

  public senderIpk: Uint8Array;

  constructor(data: Uint8Array, signature: Uint8Array, senderIpk: Uint8Array) {
    this.data = data;
    this.signature = signature;
    this.senderIpk = senderIpk;
  }

  public serialize(): Uint8Array {
    return PrismUtil.pack([
      this.data,
      this.signature,
      this.senderIpk
    ]);
  }

  public static deserialize(serializedPackage: Uint8Array): Package {
    const unpacked: Uint8Array[] = PrismUtil.unpack(serializedPackage);
    return new Package(
      unpacked[0],
      unpacked[1],
      unpacked[2],
    );
  }

  public async unpack(): Promise<EncryptedMessage> {
    if (this.senderIpk === undefined) {
      throw new Error("Sender Identity Public Key must be set in object to unpack.");
    }

    if (!PrismUtil.verifySignature(
      this.signature,
      this.data,
      this.senderIpk
    )) {
      throw new Error("Signature did not match data in package.");
    }

    return EncryptedMessage.deserialize(this.data);
  }

  public async seal(recipientEpk: Uint8Array): Promise<SealedPackage> {
    const serialized = this.serialize();
    const cipher: Uint8Array = await PrismUtil.publicEncrypt(serialized, recipientEpk);
    return new SealedPackage(cipher);
  }

}

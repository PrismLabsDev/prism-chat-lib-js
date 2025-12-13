
import * as PrismUtil from "@/Util";
import Package from "@/MessageBuilder/Package";

export default class SealedPackage {

  public readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
  }

  public async unseal(recipientEpk: Uint8Array, recipientEsk: Uint8Array): Promise<Package> {
    const decrypted: Uint8Array = await PrismUtil.publicDecrypt(
      this.data,
      recipientEpk,
      recipientEsk
    );
    return Package.deserialize(decrypted);
  }

}

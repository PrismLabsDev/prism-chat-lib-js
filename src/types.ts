
import Message from "@/MessageBuilder/Message";
import EncryptedMessage from "@/MessageBuilder/EncryptedMessage";
import Package from "@/MessageBuilder/Package";
import SealedPackage from "@/MessageBuilder/SealedPackage";

export type KeyPair = {
  pk: Uint8Array;
  sk: Uint8Array;
}

export type SessionKeyPair = {
  rx: Uint8Array;
  tx: Uint8Array;
}

export type SymmetricEncryption = {
  cipher: Uint8Array;
  nonce: Uint8Array;
  count: Uint8Array;
}

export type PersonalKeys = {
  Ipk: Uint8Array;
  Isk: Uint8Array;
  Epk: Uint8Array;
  Esk: Uint8Array;
}

export type PeerKeys = {
  Ipk: Uint8Array;
  Epk: Uint8Array;
}

export type SessionInit = {
  pk: Uint8Array;
  sk: Uint8Array;
  tx: Uint8Array | undefined;
  rx: Uint8Array | undefined;
  tx_count: number;
}

export type Session = {
  pk: Uint8Array;
  sk: Uint8Array;
  tx: Uint8Array;
  rx: Uint8Array;
  tx_count: number;
}

export type ReceiveOpenPayload = {
  layer: {
    message: undefined;
    encryptedMessage: EncryptedMessage;
    package: Package;
    sealedPackage: SealedPackage;
  }
  type: string,
  timestamp: number,
  sender: Uint8Array,
  data: Uint8Array
}

export type Layers = {
  message: Message;
  encryptedMessage: EncryptedMessage;
  package: Package;
  sealedPackage: SealedPackage;
}


import {
  type PersonalKeys,
  type PeerKeys,
  type Session,
  type SessionInit,
  type Layers,
  type ReceiveOpenPayload
} from "@/types";
import * as PrismUtil from "@/Util";
import Message from "@/MessageBuilder/Message";
import EncryptedMessage from "@/MessageBuilder/EncryptedMessage";
import Package from "@/MessageBuilder/Package";
import SealedPackage from "@/MessageBuilder/SealedPackage";

export const createUser = async (
  Ipk: Uint8Array | undefined = undefined,
  Isk: Uint8Array | undefined = undefined
): Promise<PersonalKeys> => {

  if (Ipk === undefined || Isk === undefined) {
    const { pk, sk } = await PrismUtil.createIdentityKeyPair();
    Ipk = pk;
    Isk = sk;
  }

  const Epk = await PrismUtil.deriveIdentityEncryptionPublicKey(Ipk);
  const Esk = await PrismUtil.deriveIdentityEncryptionSecretKey(Isk);

  return {
    Ipk: Ipk,
    Isk: Isk,
    Epk: Epk,
    Esk: Esk,
  }
}

export const createPeer = async (
  Ipk: Uint8Array,
): Promise<PeerKeys> => {
  const Epk = await PrismUtil.deriveIdentityEncryptionPublicKey(Ipk);
  return {
    Ipk: Ipk,
    Epk: Epk,
  }
}

export const initializeSession = async (
  user: PersonalKeys,
  peer: PeerKeys
): Promise<SessionInit> => {

  const { pk: Spk, sk: Ssk } = await PrismUtil.createSessionKeyPair();

  return {
    personalKeys: user,
    peerKeys: peer,
    pk: Spk,
    sk: Ssk,
    tx: undefined,
    rx: undefined,
    tx_count: 0,
  }
}

export const recipientExchangeSession = async (
  partialSession: SessionInit,
  peerSessionPk: Uint8Array,
): Promise<Session> => {

  const { tx, rx } = await PrismUtil.createSessionExchangeKeyPairRecipient(
    partialSession.pk,
    partialSession.sk,
    peerSessionPk
  );

  return {
    personalKeys: partialSession.personalKeys,
    peerKeys: partialSession.peerKeys,
    pk: partialSession.pk,
    sk: partialSession.sk,
    tx: tx,
    rx: rx,
    tx_count: 0,
  }
}

export const senderExchangeSession = async (
  partialSession: SessionInit,
  peerSessionPk: Uint8Array,
): Promise<Session> => {

  const { tx, rx } = await PrismUtil.createSessionExchangeKeyPairSender(
    partialSession.pk,
    partialSession.sk,
    peerSessionPk
  );

  return {
    personalKeys: partialSession.personalKeys,
    peerKeys: partialSession.peerKeys,
    pk: partialSession.pk,
    sk: partialSession.sk,
    tx: tx,
    rx: rx,
    tx_count: 0,
  }
}

// Send message skipping session symmetric encryption (usually for establishing a session)
export const sendUnencrypted = async (
  session: SessionInit,
  data: Uint8Array | string | object,
  type: string,
): Promise<{
  session: SessionInit,
  layer: Layers,
  data: Uint8Array
}> => {
  // Message builder up
  const message: Message = await Message.create(data);
  const encryptedMessage: EncryptedMessage = await message.encrypt(type);
  const package_: Package = await encryptedMessage.pack(session.personalKeys.Ipk, session.personalKeys.Isk);
  const sealedPackage: SealedPackage = await package_.seal(session.peerKeys.Epk);

  // Return updated session, message buiulder state, and payload data (raw Uint8Array to send)
  return {
    session: session,
    layer: {
      message: message,
      encryptedMessage: encryptedMessage,
      package: package_,
      sealedPackage: sealedPackage
    },
    data: sealedPackage.data
  };
}

// Exchange keys
export const send = async (
  session: Session,
  data: Uint8Array | string | object,
  type: string,
  count: number | undefined = undefined
): Promise<{
  session: Session,
  layer: Layers,
  data: Uint8Array
}> => {
  // Set count to incriment or specific count if specified
  if (count) {
    session.tx_count = count;
  } else {
    session.tx_count++;
  }

  // Derive ratcheted send key based on count
  let derivedTxKey: Uint8Array = await PrismUtil.ratchetKey(session.tx, session.tx_count);

  // Message builder up
  const message: Message = await Message.create(data);
  const encryptedMessage: EncryptedMessage = await message.encrypt(type, derivedTxKey, session.tx_count);
  const package_: Package = await encryptedMessage.pack(session.personalKeys.Ipk, session.personalKeys.Isk);
  const sealedPackage: SealedPackage = await package_.seal(session.peerKeys.Epk);

  // Return updated session, message buiulder state, and payload data (raw Uint8Array to send)
  return {
    session: session,
    layer: {
      message: message,
      encryptedMessage: encryptedMessage,
      package: package_,
      sealedPackage: sealedPackage
    },
    data: sealedPackage.data
  };
}

// Will not decrypt message as we must first know the sender and type.
export const receiveOpen = async (user: PersonalKeys, data: Uint8Array): Promise<ReceiveOpenPayload> => {
  const sealedPackage: SealedPackage = new SealedPackage(data);
  const _package: Package = await sealedPackage.unseal(user.Epk, user.Esk);
  const encryptedMessage: EncryptedMessage = await _package.unpack();

  return {
    layer: {
      sealedPackage: sealedPackage,
      package: _package,
      encryptedMessage: encryptedMessage,
      message: undefined
    },
    type: encryptedMessage.type,
    timestamp: encryptedMessage.timestamp,
    sender: _package.senderIpk,
    data: encryptedMessage.data
  }
}

// If we know the session, pass it to decrypt the message
export const receiveDecrypt = async (receiveOpenPayload: ReceiveOpenPayload, session: Session | undefined = undefined): Promise<{
  session: Session | undefined,
  layer: Layers,
  type: string,
  timestamp: number,
  sender: Uint8Array,
  data: Uint8Array
}> => {
  let derivedRxKey: Uint8Array | undefined = undefined;

  if (session && receiveOpenPayload.layer.encryptedMessage.nonce.length !== 0) {
    derivedRxKey = await PrismUtil.ratchetKey(session.rx, receiveOpenPayload.layer.encryptedMessage.count);
  }

  let message: Message = await receiveOpenPayload.layer.encryptedMessage.decrypt(derivedRxKey);

  // Return updated session, message buiulder state, and payload data (raw Uint8Array to send)
  return {
    session: session,
    layer: {
      message: message,
      encryptedMessage: receiveOpenPayload.layer.encryptedMessage,
      package: receiveOpenPayload.layer.package,
      sealedPackage: receiveOpenPayload.layer.sealedPackage
    },
    type: receiveOpenPayload.layer.encryptedMessage.type,
    timestamp: receiveOpenPayload.layer.encryptedMessage.timestamp,
    sender: receiveOpenPayload.layer.package.senderIpk,
    data: message.data,
  }
}


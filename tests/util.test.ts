
import {
  Util as PrismUtil,
  type PersonalKeys,
  type Session,
  type SymmetricEncryption,
} from "../src/index";

import * as TestHelper from "./helpers";

let alice: PersonalKeys;
let aliceSession: Session;

let bob: PersonalKeys;
let bobSession: Session;

beforeEach(async (): Promise<void> => {
  alice = await TestHelper.createUser();
  bob = await TestHelper.createUser();

  const [newAliceSession, newBobSession] = await TestHelper.createSession(alice, bob);
  aliceSession = newAliceSession;
  bobSession = newBobSession;
});

afterEach(async (): Promise<void> => { });

test('Verify exchange keys', async (): Promise<void> => {
  expect(aliceSession.tx).toStrictEqual(bobSession.rx);
  expect(aliceSession.rx).toStrictEqual(bobSession.tx);
});

test('Verify ratchet given same count', async (): Promise<void> => {

  const randomCount: number = Math.floor(Math.random() * 1000) + 1;

  const aliceSessionRatchetTx: Uint8Array = await PrismUtil.ratchetKey(aliceSession.tx, randomCount);
  const bobSessionRatchetRx: Uint8Array = await PrismUtil.ratchetKey(bobSession.rx, randomCount);

  expect(aliceSession.tx).toStrictEqual(bobSession.rx);
  expect(aliceSessionRatchetTx).toStrictEqual(bobSessionRatchetRx);
});

test('Uint8Array serialization pack', async (): Promise<void> => {
  const messages: Uint8Array[] = [
    new TextEncoder().encode("One"),
    new TextEncoder().encode("Two"),
    new TextEncoder().encode("Three"),
    new TextEncoder().encode("Four"),
    new TextEncoder().encode("Five")
  ];

  const packed: Uint8Array = PrismUtil.Uint8ArrayPack(messages);
  const unpacked: Uint8Array[] = PrismUtil.Uint8ArrayUnpack(packed);

  expect(messages).toStrictEqual(unpacked);
});

test("Symetric encrypt and decrypt", async (): Promise<void> => {
  // Alice encrypt
  const message: Uint8Array = new TextEncoder().encode("Hello World!");
  const count: Uint8Array = new TextEncoder().encode(aliceSession.tx_count.toString());
  const symmetricEncryptionObj: SymmetricEncryption = await PrismUtil.symmetricEncrypt(message, aliceSession.tx, count);

  // Bob decrypt
  const decrypted: Uint8Array = await PrismUtil.symmetricDecrypt(
    symmetricEncryptionObj.cipher,
    bobSession.rx,
    symmetricEncryptionObj.nonce,
    symmetricEncryptionObj.count
  );

  expect(decrypted).toStrictEqual(message);
});

test("Signature verification", async (): Promise<void> => {
  // Alice sign data
  const message: Uint8Array = new TextEncoder().encode("Hello World!");
  const cipher: Uint8Array = await PrismUtil.publicEncrypt(message, aliceSession.peerKeys.Epk);

  // Decrypt
  const data: Uint8Array = await PrismUtil.publicDecrypt(cipher, bobSession.personalKeys.Epk, bobSession.personalKeys.Esk);

  expect(data).toStrictEqual(message);
});

test("Public encrypt and decrypt", async (): Promise<void> => {
  // Alice sign data
  const message: Uint8Array = new TextEncoder().encode("Hello World!");
  const signature: Uint8Array = await PrismUtil.sign(message, alice.Isk);

  // Bob verify signature
  const verification: boolean = await PrismUtil.verifySignature(
    signature,
    message,
    alice.Ipk
  );

  expect(verification).toStrictEqual(true);
});

test("Uint8Array to Base64 encoding", async (): Promise<void> => {
  const message: Uint8Array = new TextEncoder().encode("Hello World!");

  const base64Encoded: string = await PrismUtil.Uint8ArrayEncodeBase64(message);

  const uint8arrayDecoded: Uint8Array = await PrismUtil.Uint8ArrayDecodeBase64(base64Encoded);

  expect(uint8arrayDecoded).toStrictEqual(message);
});



import type {
  PersonalKeys,
  Session,
  SymmetricEncryption,
} from "../src/types";

import * as PrismUtil from "../src/Util";

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
    await PrismUtil.fromString("One"),
    await PrismUtil.fromString("Two"),
    await PrismUtil.fromString("Three"),
    await PrismUtil.fromString("Four"),
    await PrismUtil.fromString("Five")
  ];

  const packed: Uint8Array = PrismUtil.pack(messages);
  const unpacked: Uint8Array[] = PrismUtil.unpack(packed);

  expect(messages).toStrictEqual(unpacked);
});

test("Symmetric encrypt and decrypt", async (): Promise<void> => {
  // Alice encrypt
  const message: Uint8Array = await PrismUtil.fromString("Hello World!");
  const count: Uint8Array = await PrismUtil.fromString(aliceSession.tx_count.toString());
  const symmetricEncryptionObj: SymmetricEncryption = await PrismUtil.symmetricEncrypt(message, aliceSession.tx, undefined, count);

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
  const message: Uint8Array = await PrismUtil.fromString("Hello World!");
  const cipher: Uint8Array = await PrismUtil.publicEncrypt(message, bob.Epk);

  // Decrypt
  const data: Uint8Array = await PrismUtil.publicDecrypt(cipher, bob.Epk, bob.Esk);

  expect(data).toStrictEqual(message);
});

test("Public encrypt and decrypt", async (): Promise<void> => {
  // Alice sign data
  const message: Uint8Array = await PrismUtil.fromString("Hello World!");
  const signature: Uint8Array = await PrismUtil.sign(message, alice.Isk);

  // Bob verify signature
  const verification: boolean = await PrismUtil.verifySignature(
    signature,
    message,
    alice.Ipk
  );

  expect(verification).toStrictEqual(true);
});

test("To from string encoding", async (): Promise<void> => {
  const messageStr: string = "Hello World!";

  const encoded: Uint8Array = await PrismUtil.fromString(messageStr);

  const decoded: string = await PrismUtil.toString(encoded);

  expect(decoded).toStrictEqual(messageStr);
});

test("To from Base64 encoding", async (): Promise<void> => {
  const message: Uint8Array = await PrismUtil.fromString("Hello World!");

  const base64Encoded: string = await PrismUtil.toBase64(message);

  const uint8arrayDecoded: Uint8Array = await PrismUtil.fromBase64(base64Encoded);

  expect(uint8arrayDecoded).toStrictEqual(message);
});

test("Symmetric password encryption", async (): Promise<void> => {
  const password: string = "Password#123";
  const message: Uint8Array = await PrismUtil.fromString("Hello World!");

  let key: Uint8Array = new Uint8Array(0);
  let nonce: Uint8Array = new Uint8Array(0);
  let salt: Uint8Array = new Uint8Array(0);

  let symKeys1 = await PrismUtil.createSymmetricKey(password);
  key = symKeys1.key;
  nonce = symKeys1.nonce;
  salt = symKeys1.salt;

  const encrypted = await PrismUtil.symmetricEncrypt(
    message,
    key,
    nonce
  );

  let symKeys2 = await PrismUtil.createSymmetricKey(password, salt, nonce);
  key = symKeys2.key;

  const decrypted: Uint8Array = await PrismUtil.symmetricDecrypt(
    encrypted.cipher,
    key,
    nonce
  );

  expect(decrypted).toStrictEqual(message);
  expect(encrypted.nonce).toStrictEqual(nonce);
});


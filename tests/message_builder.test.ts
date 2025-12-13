
import {
  MessageBuilder as PrismMB,
  type PersonalKeys,
  type Session,
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

test("Message Up Down", async (): Promise<void> => {
  const messageText: string = "Hello World!";

  // Alice Send
  const sendMessage: PrismMB.Message = new PrismMB.Message(messageText);

  expect(sendMessage.strDecode()).toStrictEqual(messageText);
});

test("EncryptedMessage Up Down", async (): Promise<void> => {
  const messageText: string = "Hello World!";

  // Alice Send
  const sendMessage: PrismMB.Message = new PrismMB.Message(messageText);
  const sendEncryptedMessage: PrismMB.EncryptedMessage = await sendMessage.encrypt("a", aliceSession.tx, aliceSession.tx_count);
  const sendEncryptedMessageSerialized: Uint8Array = await sendEncryptedMessage.serialize();

  // Bob Receive
  const receiveEncryptedMessage: PrismMB.EncryptedMessage = await PrismMB.EncryptedMessage.deserialize(sendEncryptedMessageSerialized);
  const receiveMessage: PrismMB.Message = await receiveEncryptedMessage.decrypt(bobSession.rx);

  expect(receiveMessage.strDecode()).toStrictEqual(messageText);
});

test("Package Up Down", async (): Promise<void> => {
  const messageText: string = "Hello World!";

  // Alice Send
  const sendMessage: PrismMB.Message = new PrismMB.Message(messageText);
  const sendEncryptedMessage: PrismMB.EncryptedMessage = await sendMessage.encrypt("a", aliceSession.tx, aliceSession.tx_count);
  const sendPackage: PrismMB.Package = await sendEncryptedMessage.pack(aliceSession.personalKeys.Ipk, aliceSession.personalKeys.Isk);
  const sendPackageSerialized: Uint8Array = await sendPackage.serialize();

  // Bob Receive
  const receivePackage: PrismMB.Package = await PrismMB.Package.deserialize(sendPackageSerialized);
  const receiveEncryptedMessage: PrismMB.EncryptedMessage = await receivePackage.unpack();
  const receiveMessage: PrismMB.Message = await receiveEncryptedMessage.decrypt(bobSession.rx);

  expect(receiveMessage.strDecode()).toStrictEqual(messageText);
});

test("SealedPackage Up Down", async (): Promise<void> => {
  const messageText: string = "Hello World!";

  // Alice Send
  const sendMessage: PrismMB.Message = new PrismMB.Message(messageText);
  const sendEncryptedMessage: PrismMB.EncryptedMessage = await sendMessage.encrypt("a", aliceSession.tx, aliceSession.tx_count);
  const sendPackage: PrismMB.Package = await sendEncryptedMessage.pack(aliceSession.personalKeys.Ipk, aliceSession.personalKeys.Isk);
  const sendSealedPackage: PrismMB.SealedPackage = await sendPackage.seal(aliceSession.peerKeys.Epk);

  // Bob Receive
  const receiveSealedPackage: PrismMB.SealedPackage = new PrismMB.SealedPackage(sendSealedPackage.data);
  const receivePackage: PrismMB.Package = await receiveSealedPackage.unseal(bobSession.personalKeys.Epk, bobSession.personalKeys.Esk);
  const receiveEncryptedMessage: PrismMB.EncryptedMessage = await receivePackage.unpack();
  const receiveMessage: PrismMB.Message = await receiveEncryptedMessage.decrypt(bobSession.rx);

  expect(receiveMessage.strDecode()).toStrictEqual(messageText);
});


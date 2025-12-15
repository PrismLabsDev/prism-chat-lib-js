
import type { Session, PersonalKeys } from "../src/types";
import * as PrismUtil from "../src/Util";
import {
  createUser as PrismCreateUser,
  createPeer as PrismCreatePeer,
  initializeSession as PrismInitializeSession,
  senderExchangeSession as PrismSenderExchangeSession,
  recipientExchangeSession as PrismRecipientExchangeSession,
  send as PrismSend,
  sendUnencrypted as PrismSendUnencrypted,
  receiveOpen as PrismReceiveOpen,
  receiveDecrypt as PrismReceiveDecrypt,
} from "../src/Main";

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

test("Generate identity.", async (): Promise<void> => {
  const alice = await PrismCreateUser();

  const aliceEpkVerify = await PrismUtil.deriveIdentityEncryptionPublicKey(alice.Ipk);
  const aliceEskVerify = await PrismUtil.deriveIdentityEncryptionSecretKey(alice.Isk);

  expect(alice).toBeDefined();
  expect(alice.Epk).toEqual(aliceEpkVerify);
  expect(alice.Esk).toEqual(aliceEskVerify);
});

test("Load existing identity.", async (): Promise<void> => {
  const alicePrevious = await PrismCreateUser();
  const alice = await PrismCreateUser(alicePrevious.Ipk, alicePrevious.Isk);

  const aliceEpkVerify = await PrismUtil.deriveIdentityEncryptionPublicKey(alice.Ipk);
  const aliceEskVerify = await PrismUtil.deriveIdentityEncryptionSecretKey(alice.Isk);

  expect(alice).toBeDefined();
  expect(alice.Epk).toEqual(aliceEpkVerify);
  expect(alice.Esk).toEqual(aliceEskVerify);
});

test("Send & receive message.", async (): Promise<void> => {

  const messageStr = "Hello World!";

  // Send
  const sendObj = await PrismSend(aliceSession, messageStr, "m");
  aliceSession = sendObj.session;

  const sendToBob = sendObj.data;

  // Receive
  const receiveByAliceOpen = await PrismReceiveOpen(bob, sendToBob);
  const receiveByAliceDecrypted = await PrismReceiveDecrypt(receiveByAliceOpen, bobSession);

  expect(aliceSession.tx_count).toEqual(1); // Verify the session was updated
  expect(receiveByAliceOpen.type).toEqual("m"); // Verify type is message
  expect(await receiveByAliceDecrypted.layer.message.strDecode()).toEqual(messageStr); // Verify message equals the input
});

test("Send & receive message unencrypted.", async (): Promise<void> => {

  const messageStr = "Hello World!";

  // Send
  const sendObj = await PrismSendUnencrypted(aliceSession, messageStr, "m");
  const sendToBob = sendObj.data;

  // Receive
  const receiveByAliceOpen = await PrismReceiveOpen(bob, sendToBob);
  const receiveByAliceDecrypted = await PrismReceiveDecrypt(receiveByAliceOpen, bobSession);

  expect(receiveByAliceOpen.type).toEqual("m"); // Verify type is message
  expect(await PrismUtil.toString(receiveByAliceOpen.data)).toEqual(messageStr); // Verify the Encrypted message data matches send message
  expect(await receiveByAliceDecrypted.layer.message.strDecode()).toEqual(messageStr); // Verify message decrypt is equal to sent message
});

test("Create shared session.", async (): Promise<void> => {
  // Alice and Bob sessions are templated for each test, they are overwritten in test.

  // Alice gets Bob's Ipk and creates a peer then initializes a session
  // ---
  // Performed by: ALICE
  // Known: Bob Ipk
  const alicePeer = await PrismCreatePeer(bob.Ipk);
  const aliceSessionInit = await PrismInitializeSession(alice, alicePeer);

  const payloadIC: any = PrismUtil.pack([
    aliceSessionInit.pk,
    await PrismUtil.fromString("Alice"),
    await PrismUtil.fromString("Let's chat."),
  ]);

  const aliceSendIC = await PrismSendUnencrypted(
    aliceSessionInit,
    payloadIC,
    "ic"
  );

  let sendToBob: Uint8Array = aliceSendIC.data; // What is sent in message



  // Alice sends her session pk bob.
  // Bob then generates his own session, generates shared keys, replies with his session pk.
  // ---
  // Performed by BOB
  // Known: Alice Ipk, Alice session pk
  const bobReceiveICOpen = await PrismReceiveOpen(bob, sendToBob);
  expect(bobReceiveICOpen.type).toEqual("ic");
  const bobReceiveICDecrypted = await PrismReceiveDecrypt(bobReceiveICOpen);

  // Read payload
  const payloadReadIC = PrismUtil.unpack(bobReceiveICDecrypted.data);
  expect(payloadReadIC[0]).toEqual(aliceSessionInit.pk);
  expect(await PrismUtil.toString(payloadReadIC[1])).toEqual("Alice");
  expect(await PrismUtil.toString(payloadReadIC[2])).toEqual("Let's chat.");

  const bobPeer = await PrismCreatePeer(bobReceiveICDecrypted.sender);
  const bobSessionInit = await PrismInitializeSession(bob, bobPeer);
  bobSession = await PrismRecipientExchangeSession(bobSessionInit, payloadReadIC[0]); // Reset helper bobSession.

  const payloadRC: any = PrismUtil.pack([
    bobSession.pk,
    await PrismUtil.fromString("Bob"),
    await PrismUtil.fromString("I Agree!"),
  ]);

  const bobSendRC = await PrismSendUnencrypted(
    bobSession,
    payloadRC,
    "rc"
  );

  let sendToAlice: Uint8Array = bobSendRC.data; // What is sent in message



  // Bob replies to Alice with his session pk,
  // Alice then generates her own shared keys with Bob's session pk.
  // ---
  // Performed by ALICE
  // Known: Bob session pk
  const aliceReceiveRCOpen = await PrismReceiveOpen(alice, sendToAlice);
  expect(aliceReceiveRCOpen.type).toEqual("rc");
  const aliceReceiveRCDecrypted = await PrismReceiveDecrypt(aliceReceiveRCOpen);

  // Read payload
  const payloadReadRC = PrismUtil.unpack(aliceReceiveRCDecrypted.data);
  expect(payloadReadRC[0]).toEqual(bobSessionInit.pk);
  expect(await PrismUtil.toString(payloadReadRC[1])).toEqual("Bob");
  expect(await PrismUtil.toString(payloadReadRC[2])).toEqual("I Agree!");

  aliceSession = await PrismSenderExchangeSession(aliceSessionInit, payloadReadRC[0]); // Reset helper aliceSession.



  // Now we have a shared session and can send fully encrypted messages.
  expect(aliceSession.tx).toEqual(bobSession.rx);
  expect(aliceSession.rx).toEqual(bobSession.tx);
});

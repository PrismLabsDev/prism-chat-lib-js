import type { PersonalKeys, Session } from "../src/types";
import {
  send as PrismSend,
  receiveOpen as PrismReceiveOpen,
  receiveDecrypt as PrismReceiveDecrypt
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

test("Alice and Bob sessions exist", async (): Promise<void> => {
  expect(alice).toBeDefined();
  expect(aliceSession).toBeDefined();

  expect(bob).toBeDefined();
  expect(aliceSession).toBeDefined();
});

test("Generate shared session", async (): Promise<void> => {
  expect(aliceSession.tx).toStrictEqual(bobSession.rx);
  expect(aliceSession.rx).toStrictEqual(bobSession.tx);
});

test("Send and Receive high level operations.", async (): Promise<void> => {
  const messageText: string = "Hello World!";

  const {
    session: sendSession,
    layer: sendLayer,
    data: sendData
  } = await PrismSend(aliceSession, messageText, "a");
  aliceSession = sendSession;

  // Must open first to know ender Ipk
  const receiveOpenData = await PrismReceiveOpen(bob, sendData);
  const {
    session: receiveSession,
    layer: receiveLayer,
    data: receiveData
  } = await PrismReceiveDecrypt(receiveOpenData, bobSession);

  expect(await receiveLayer.message.strDecode()).toStrictEqual(messageText);
});

test("Send and Receive high level operations skip encryption layer (For IC & RC)", async (): Promise<void> => {
  const messageText: string = "Hello World!";

  const {
    session: sendSession,
    layer: sendLayer,
    data: sendData
  } = await PrismSend(aliceSession, messageText, "IC");
  aliceSession = sendSession;

  // Must open first to know ender Ipk
  const receiveOpenData = await PrismReceiveOpen(bob, sendData);
  const {
    session: receiveSession,
    layer: receiveLayer,
    data: receiveData
  } = await PrismReceiveDecrypt(receiveOpenData, bobSession);

  expect(await receiveLayer.message.strDecode()).toStrictEqual(messageText);
});

test("Send and Receive high level operations message stream.", async (): Promise<void> => {
  const messages: string[] = [
    "one",
    "two",
    "three"
  ];

  // Send stream of 3 messages
  const {
    session: sendSession1,
    layer: sendLayer1,
    data: sendData1
  } = await PrismSend(aliceSession, messages[0], "a");
  aliceSession = sendSession1;

  const {
    session: sendSession2,
    layer: sendLayer2,
    data: sendData2
  } = await PrismSend(aliceSession, messages[1], "a");
  aliceSession = sendSession2;

  const {
    session: sendSession3,
    layer: sendLayer3,
    data: sendData3
  } = await PrismSend(aliceSession, messages[2], "a");
  aliceSession = sendSession3;

  // Receive stream of 3 messages
  const receiveOpen1 = await PrismReceiveOpen(bob, sendData1);
  const {
    session: receiveSession1,
    layer: receiveLayer1,
    data: receiveData1
  } = await PrismReceiveDecrypt(receiveOpen1, bobSession);
  receiveSession1 ? bobSession = receiveSession1 : undefined;

  const receiveOpen2 = await PrismReceiveOpen(bob, sendData2);
  const {
    session: receiveSession2,
    layer: receiveLayer2,
    data: receiveData2
  } = await PrismReceiveDecrypt(receiveOpen2, bobSession);
  receiveSession2 ? bobSession = receiveSession2 : undefined;


  const receiveOpen3 = await PrismReceiveOpen(bob, sendData3);
  const {
    session: receiveSession3,
    layer: receiveLayer3,
    data: receiveData3
  } = await PrismReceiveDecrypt(receiveOpen3, bobSession);
  receiveSession3 ? bobSession = receiveSession3 : undefined;


  expect(await receiveLayer1.message.strDecode()).toStrictEqual(messages[0]);
  expect(await receiveLayer2.message.strDecode()).toStrictEqual(messages[1]);
  expect(await receiveLayer3.message.strDecode()).toStrictEqual(messages[2]);
});

test("Send and Receive high level operations message stream skip encryption layer. (For IC & RC)", async (): Promise<void> => {
  const messages: string[] = [
    "one",
    "two",
    "three"
  ];

  // Send stream of 3 messages
  const {
    session: sendSession1,
    layer: sendLayer1,
    data: sendData1
  } = await PrismSend(aliceSession, messages[0], "a");
  aliceSession = sendSession1;

  const {
    session: sendSession2,
    layer: sendLayer2,
    data: sendData2
  } = await PrismSend(aliceSession, messages[1], "a");
  aliceSession = sendSession2;

  const {
    session: sendSession3,
    layer: sendLayer3,
    data: sendData3
  } = await PrismSend(aliceSession, messages[2], "a");
  aliceSession = sendSession3;

  // Receive stream of 3 messages
  const receiveOpen1 = await PrismReceiveOpen(bob, sendData1);
  const {
    session: receiveSession1,
    layer: receiveLayer1,
    data: receiveData1
  } = await PrismReceiveDecrypt(receiveOpen1, bobSession);
  receiveSession1 ? bobSession = receiveSession1 : undefined;

  const receiveOpen2 = await PrismReceiveOpen(bob, sendData2);
  const {
    session: receiveSession2,
    layer: receiveLayer2,
    data: receiveData2
  } = await PrismReceiveDecrypt(receiveOpen2, bobSession);
  receiveSession1 ? bobSession = receiveSession1 : undefined;

  const receiveOpen3 = await PrismReceiveOpen(bob, sendData3);
  const {
    session: receiveSession3,
    layer: receiveLayer3,
    data: receiveData3
  } = await PrismReceiveDecrypt(receiveOpen3, bobSession);
  receiveSession1 ? bobSession = receiveSession1 : undefined;

  expect(await receiveLayer1.message.strDecode()).toStrictEqual(messages[0]);
  expect(await receiveLayer2.message.strDecode()).toStrictEqual(messages[1]);
  expect(await receiveLayer3.message.strDecode()).toStrictEqual(messages[2]);
});


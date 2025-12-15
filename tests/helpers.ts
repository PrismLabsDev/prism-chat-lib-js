import type { PersonalKeys, Session } from "../src/types";
import {
  createUser as PrismCreateUser,
  createPeer as PrismCreatePeer,
  initializeSession as PrismInitializeSession,
  senderExchangeSession as PrismSenderExchangeSession,
  recipientExchangeSession as PrismRecipientExchangeSession,
} from "../src/Main";

export const createUser = async (): Promise<PersonalKeys> => {
  return await PrismCreateUser();
}

export const createSession = async (alice: PersonalKeys, bob: PersonalKeys): Promise<[Session, Session]> => {

  // Alice gets Bob's Ipk and creates a peer then initializes a session
  // Performed by: ALICE
  const alicePeer = await PrismCreatePeer(bob.Ipk);
  const aliceSessionInit = await PrismInitializeSession();

  // Alice sends her session pk bob.
  // Bob then generates his own session, generates shared keys, replies with his session pk.
  // Performed by BOB
  const bobPeer = await PrismCreatePeer(alice.Ipk);
  const bobSessionInit = await PrismInitializeSession();
  const bobSession = await PrismRecipientExchangeSession(bobSessionInit, aliceSessionInit.pk);

  // Bob replies to Alice with his session pk,
  // Alice then generates her own shared keys with Bob's session pk.
  // Performed by ALICE
  const aliceSession = await PrismSenderExchangeSession(aliceSessionInit, bobSessionInit.pk);

  // Now we have a shared session and can send fully encrypted messages.

  return [aliceSession, bobSession];
}


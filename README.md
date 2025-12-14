# Prism Chat Lib JS

Prism Chat Encryption provides the cryptographic foundation for the Prism Chat protocol. It wraps [libsodium-wrappers-sumo](https://www.npmjs.com/package/libsodium-wrappers-sumo), offering a clean JavaScript API for secure messaging operations, including:

- Basic cryptographic operations (key generation, signing, encryption, binary serialization).
- Prism protocol MessageBuilder with up/down serialization methods for each layer.
- High-level methods for common actions and standard data structure definitions.

This module isolates cryptographic details from the rest of the Prism Chat stack, keeping protocol logic clean, maintainable and portable.

Prism Chat relies on [libsodium](https://doc.libsodium.org/doc), a widely used cryptographic library, making it easier to implement the protocol across different languages. By depending on [libsodium-wrappers-sumo](https://www.npmjs.com/package/libsodium-wrappers-sumo) (WebAssembly build), Prism Chat Encryption runs efficiently in browsers, Node.js, and other JavaScript runtimes.

## Usage

This library can be more easily understood by breaking it down into its main components:

- Exported, initialized WebAssembly-backed sodium instance used by the library
- Cryptographic utility methods — abstractions over sodium
- MessageBuilder class system for handling each layer of the protocol
- High-level methods for common operations

If you’re building an application compatible with the Prism Chat protocol, you will most likely only need the high-level methods. These methods handle most of the heavy lifting for you, while the lower-level utility functions and sodium abstractions are still exposed if you need full control.

Cryptographic primitives in this library operate primarily on binary data. Most operations produce binary output in the form of `Uint8Array`. By itself, this binary data loses context, which can make it difficult to manage. Our high-level methods use a type system to maintain context and structure, making it easier to work with cryptographic data safely and predictably.

### High level operations

As mentioned earlier, these methods handle most of the heavy lifting if you are building a solution fully compatible with the Prism Chat protocol. They simplify the management of binary data through our type system and make it easy to implement a working application.

The common operations provided at a high level include:

- Generating user keys
- Initializing a session between two users
- Sending and receiving messages

Note: In our examples, we use the names `Alice` and `Bob` to represent two different users. Each user is assumed to be performing these operations on their own computer, independently of one another.

#### Generating user keys

The first step is to generate a set of `PersonalKeys` for the user. These keys represent the user's identity and are used for signing and identifying them. Once established, these keys must be stored persistently. If they are lost, other users will not be able to verify future messages from you.

If you pass no parameters it will generate a new set of keys for you. Producing an identity keypair. If you need to initialize a new `PersonalKeys` object, you can pass your existing identity keys to the method.

``` js
import {
 createUser,
 type PersonalKeys,
} from "@prismlabsdev/prism-chat-lib-js";

// Generate new keys
const newKeys: PersonalKeys = createUser();

// Use existing identity keys (Assume Ipk & Isk are saved)
const initializeExistingUser: PersonalKeys = createUser(Ipk, Isk);
```

#### Initialize session

Initializing a session between two users requires at least two messages to exchange the necessary keys. Prism Chat uses a triple Diffie-Hellman key exchange so that both users can derive the same send and receive keys for the session (tx & rx). This process is used for the third layer of the Prism protocol (Encrypt Message), which provides the highest level of security.

The advantage of the triple Diffie-Hellman exchange is that it can be performed entirely over an unencrypted channel. However, the first two layers of the Prism protocol are still applied. These layers provide:

- Basic public-key encryption
- Metadata packing, including timestamp, message type, sender address, and signature verification

All of these steps are necessary for secure communication and proper session management.

**Note**: In this example, we will skip the operations for generating the actual binary payload of the message, as this is demonstrated in the next example. During the session setup:

- The `SessionInit` object should be saved and replaced only when a full `Session` is established.
- The full Session contains the derived `tx` and `rx` keys needed for all layers of encryption.

The first two layers can be performed using only the `SessionInit` (without `tx` & `rx` keys).

``` js
import {
  createPeer,
  initializeSession,
  recipientExchangeSession,
  senderExchangeSession,
  type PeerKeys,
  type PersonalKeys,
  type SessionInit,
  type Session
} from "@prismlabsdev/prism-chat-lib-js";


// Step 1 (IC): Alice knows Bob's public identity key and wants to establish a session.
const bobPublicKey: Uint8Array; // Assume already initialized
const alice: PersonalKeys; // Assume already initialized

const alicePeer: PeerKeys = await createPeer(bobPublicKey); // Alice generates a set of peer keys from Bob's public key
const aliceSessionInit: SessionInit = await initializeSession(alice, alicePeer); // Alice initializes a session

const sendToBob: Uint8Array = aliceSessionInit.pk; // This message type is called "ic"" (initial communication)


// Step 2 (RC): Bob receives the session public key from Alice, generates his own session, performs the key exchange, sends his session public key.
const alicePublicKey: Uint8Array; // Known when opening the message payload (in next example)
const bob: PersonalKeys; // Assume already initialized

const bobPeer: PeerKeys = await createPeer(alicePublicKey); // Generate peer from now known sender
const bobSessionInit: SessionInit = await initializeSession(bob, bobPeer); // Generate initial session object
const bobSession: Session = await recipientExchangeSession(bobSessionInit, sendToBob); // Combine initial session with Alice sent session pk to create full session (shared tx & rx)

const sendToAlice: Uint8Array = bobSession.pk; // Also works with bobSessionInit.pk This message type is "rc" (response communication)


// Step 3: Alice receives the session public key from bob, combines it with her initial session and performs the key exchange herself.
const aliceSession: Session = await senderExchangeSession(aliceSessionInit, sendToAlice); // Combine initial session with Alice sent session pk to create full session (shared tx & rx)


// Now Alice and Bob have a shared session with matching send and receive keys (tx & rx) and can send fully encrypted messages
```

#### Sending & Receiving Messages

Sending and receiving messages is simplified using the library’s high-level methods:

- Sending without a session: If no session is established, you can send a message without the third layer of encryption using `sendUnencrypted()`. Pass a `SessionInit` object along with the data and message type. This skips the third layer of encryption.
- Sending with a session: If a session is established, use `send()` with a `Session` object, data, and message type. This performs all three layers of encryption.
- Receiving a message (first two layers): Use `receiveOpen()` with your `PersonalKeys` and the received binary payload. This extracts the sender, timestamp, verifies the signature, and checks the message type.
- Final layer of decryption (third layer): Use `receiveDecrypt()`. Optionally pass the `Session` you have with the sender to perform the third layer of decryption. If no session is passed, the third layer is skipped (used for messages of type `ic` or `rc`).

The `send()` method returns a modified Session object with an incremented session count, which is used for key derivation and to ensure forward security.

Some message types require compound data structures. For example, `ic` and `rc` type messages contain the generated session public key, along with the user’s desired name and a one-time message. This helps the recipient identify the user requesting a session.

We use a binary serialization method to keep the data compact (`Util.Uint8ArrayPack()` & `Util.Uint8ArrayUnpack()`):

- Create an array of `Uint8Array` elements in a specific order.
- Pass this array to the serialization method to generate headers for each element.
- Pack them into a single `Uint8Array` for serialization.

The recipient can then unpack the single `Uint8Array` message into its constituent parts, using the known format for the given message type.

``` js
import {
  Util as PrismUtil,
  sendUnencrypted,
  send,
  receiveOpen,
  receiveDecrypt
} from "@prismlabsdev/prism-chat-lib-js";


// Create IC message payload
const sessionPK: Uint8Array; // Known after SessionInit
const packedIC: Uint8Array = PrismUtil.Uint8ArrayPack([
  sessionPK,
  new TextEncoder().encode("Alice"),
  new TextEncoder().encode("Let's chat!"),
]);
const unpackedIC: Uint8Array[] = PrismUtil.Uint8ArrayUnpack(packedIC);


// Send and receive unencrypted message (ic & rc)
// Alice send
const messageUnencrypted = await sendUnencrypted(
  aliceSessionInit, // SessionInit
  packedIC,         // payload data
  "ic"              // Message type string
);
const sendToBob: Uint8Array = messageUnencrypted.data;

// Bob receive
const receiveUnencryptedOpen = await receiveOpen(bob, sendToBob);
const receiveUnencryptedDecrypted = await receiveDecrypt(receiveUnencryptedOpen, undefined);
const received: Uint8Array = receiveUnencryptedDecrypted.data;


// Send and receive encrypted message (m)
// Alice send
const messageEncrypted = await send(
  aliceSession,   // Session
  "Hello World!", // payload data
  "t"             // Message type string
);
const sendToBob: Uint8Array = messageEncrypted.data;

// Bob receive
const receiveEncryptedOpen = await receiveOpen(bob, sendToBob);
const receiveEncryptedDecrypted = await receiveDecrypt(receiveEncryptedOpen, bobSession);
const received: Uint8Array = receiveEncryptedDecrypted.data;
```

##### Message Types

When generating a message to send, you must supply the following:

- Session object: Contains your keys, your peer’s keys, and the session’s ephemeral keys.
- Payload: A `Uint8Array` representing the binary payload. If another type is passed, it is automatically converted.
- Type: A string representing the message type. This is serialized to a binary `Uint8Array`.

###### Default Types

- **ic** — Initial communication. A compound type used to initiate a session. Contains the generated session public key, the sender’s name, and a one-time message.
- **rc** — Response communication. A compound type used to respond to an `ic` message. Contains the generated session public key, the sender’s name, and a one-time message.
- **t** — Text message. A non-compound type used to send a text payload.

We support several default message types and payload formats. You may also use custom types by prefixing the type name with an underscore (e.g., `_customtype`).

###### Compound and Non-Compound Payloads

The payload must always be a `Uint8Array`. Some message types (such as `ic` and `rc`) require compound payloads — ordered sequences of fields. Instead of converting an object to JSON and then to binary, we use a binary serialization method that packs an array of `Uint8Array` values into a single array. This is handled by our `Uint8ArrayPack()` and `Uint8ArrayUnpack()` methods.

Each compound type defines its own field order, and each field must be converted to a `Uint8Array` before packing.

Note: Text (t) messages are not compound types, so packing is not required. You can manually convert the string to a `Uint8Array`, or simply pass the string to `send()` or `sendUnencrypted()`, and it will be converted automatically.

``` js
// Examples of building default message types.

// ic: Initial communication type
const ic: Uint8Array = PrismUtil.Uint8ArrayPack([
  sessionPK,                                                        // Generates session pk
  new TextEncoder().encode("Alice"),                                // Name of user
  new TextEncoder().encode("I want to make a session with you."),   // One time message
]);
const unpacked_ic: Uint8Array[] = PrismUtil.Uint8ArrayUnpack(ic);   // [sessionPK, name, message]

// rc: Response communication type
const rc: Uint8Array = PrismUtil.Uint8ArrayPack([
  sessionPK,                                                        // Generates session pk
  new TextEncoder().encode("Bob"),                                  // Name of user
  new TextEncoder().encode("I agree, lets make a session."),        // One time message
]);
const unpacked_rc: Uint8Array[] = PrismUtil.Uint8ArrayUnpack(ic);   // [sessionPK, name, message]

// t: Text type (Not compound, no packing required)
const t: Uint8Array = new TextEncoder().encode("Hey! Hows it going?");
const unpacked_t: string = new TextDecoder().decode(t);             // "Hey! Hows it going?"
```

### Message builder

The Message Builder is a class-based system that manages the full encryption pipeline for a message. Each encryption layer requires its own serialization step, and the Message Builder automates this process. Every layer is implemented as a separate class with methods for serializing itself and constructing the next layer either upward (packing/sealing) or downward (unpacking/decrypting). The system follows a builder-style, chainable design.

Although it can be used directly, the Message Builder is primarily an internal mechanism leveraged by the library’s high-level send and receive operations.

High-level methods built on top of the Message Builder also handle:

- Automatic message count incrementing
- Send key derivation
- Updating session objects with new state

This system ensures that all layers of encryption, key management, and session state are handled consistently and securely.

#### Message builder: Encrypt

``` js
// Known by alice for encrypt
const alice: PersonalKeys; // Already known
const aliceSession: Session; // Already known after session established

const messageStr = "Hello World!";

// Alice Encrypt
const message: Message = new Message(messageStr);
const encryptedMessage: EncryptedMessage = await message.encrypt("m", aliceSession.tx, aliceSession.tx_count);
const package_: Package = await encryptedMessage.pack(aliceSession.personalKeys.Ipk, aliceSession.personalKeys.Isk);
const sealedPackage: SealedPackage = await package_.seal(aliceSession.peerKeys.Epk);

const send: Uint8Array = sealedPackage.data; // Binary data sent to Bob
```

#### Message builder: Decrypt

``` js
// Known by bob for decrypt
const bob: PersonalKeys; // Already known
const bobSession: Session; // Already known after session established

// Decrypt
const sealedPackage: SealedPackage = new SealedPackage(send);
const _package: Package = await sealedPackage.unseal(bob.Epk, bob.Esk);
const encryptedMessage: EncryptedMessage = await _package.unpack();
const message: Message = await encryptedMessage.decrypt(bobSession.rx);

const receivedStr = message.strDecode();

// Result
receivedStr == messageStr;
```

### Cryptography primitive utility functions

These are pure functions built on top of [libsodium](https://doc.libsodium.org/doc) to separate the low-level cryptography from higher-level abstractions, such as the Message Builder and high-level operations. This separation also allows us to clearly define which sodium methods are used for each specific cryptographic operation.

Note: In most cases, you will only need `Uint8ArrayPack()` and `Uint8ArrayUnpack()`. These functions are used to compactly serialize multiple items into a single `Uint8Array` for transmission.

``` js
// Generate an Identity keypair
const { pk: Uint8Array, sk: Uint8Array } = await createIdentityKeyPair();

// Derive an encryption public key from identity public key
const Epk: Uint8Array = await deriveIdentityEncryptionPublicKey(
  Ipk: Uint8Array
);

// Derive an encryption secret key from identity secret key
const Esk: Uint8Array = await deriveIdentityEncryptionSecretKey(
  Isk: Uint8Array
);

// Generate the session keypair for exchange
const {
  pk: Uint8Array,
  sk: Uint8Array
} = createSessionKeyPair(
  Isk: Uint8Array
);

// Recipient join session keypair with received peer session pk to generate shared tx and rx keys
const {
  tx: Uint8Array,
  rx: Uint8Array
} = await createSessionExchangeKeyPairRecipient(
  Spk: Uint8Array,
  Ssk: Uint8Array,
  Spk_peer: Uint8Array
);

// Sender join session keypair with received peer session pk to generate shared tx and rx keys
const {
  tx: Uint8Array,
  rx: Uint8Array
} = await createSessionExchangeKeyPairSender(
  Spk: Uint8Array,
  Ssk: Uint8Array,
  Spk_peer: Uint8Array
);

// Ratchet key for forward security based on count (does not need to be sequential)
const ratchetedKey: Uint8Array = await ratchetKey(
  key: Uint8Array,
  count: number
);

// Symmetric encryption (Usually use session tx)
const {
  cipher: Uint8Array,
  nonce: Uint8Array,
  count: Uint8Array
} = await symmetricEncrypt(
  data: Uint8Array,
  key: Uint8Array,
  count: Uint8Array
);

// Symmetric decrypt (Usually use session rx)
const data: Uint8Array = await symmetricDecrypt(
  cipher: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  count: Uint8Array
);

// Generate signature for data with identity secret key
const signature: Uint8Array = await sign(
  data: Uint8Array,
  key: Uint8Array
);

// verify signature for data with identity public key
const valid: boolean = await verifySignature(
  signature: Uint8Array,
  data: Uint8Array,
  key: Uint8Array
);

// Encrypt data with public key (derived from public identity key)
const cipher: Uint8Array = await publicEncrypt(
  data: Uint8Array,
  key: Uint8Array
);

// Decrypt data with secret key (derived from secret identity key)
const data: Uint8Array = await publicDecrypt(
  cipher: Uint8Array,
  pubKey: Uint8Array,
  prvKey: Uint8Array
);

// Standard binary serialization method for joining multiple Uint8Array
const data: Uint8Array = Uint8ArrayPack(
  parts: Uint8Array[]
);

// Standard binary deserialization method for joined Uint8Array
const parts: Uint8Array[] = Uint8ArrayUnpack(
  data: Uint8Array
);

// Encode a Uint8Array to base64 string URL safe without padding
const data: string = Uint8ArrayEncodeBase64(
  arr: Uint8Array
);

// Decode a base64 string URL safe without padding to Uint8Array
const data: Uint8Array = Uint8ArrayDecodeBase64(
  str: string
);
```

## The Protocol

The Prism Protocol is built on top of [libsodium](https://doc.libsodium.org/doc) cryptographic primitives to provide end-to-end encrypted (E2EE), decentralized, and anonymous messaging. While primarily designed for chat, it can handle arbitrary binary data.

At its core, the protocol relies on just a few cryptographic operations:

- Symmetric Encryption: XChaCha20-Poly1305
- Signatures: Ed25519
- Public-Key Encryption: Curve25519

### Messages

Prism Chat uses three layers of encryption and serialization to ensure privacy and authenticity. Each layer has an “up” and “down” method to transform the data, and each is represented by a separate class in the library.

#### Layer 1: Encrypt

The Encrypt layer protects the payload itself, without metadata.

- Payload is encrypted symmetrically using the sender’s `tx` key and decrypted using the recipient’s `rx` key.
- Keys are derived from the session key exchange and ratcheted per message using the message count (from the Pack layer) to provide forward secrecy.
- Output: ciphertext and nonce.

#### Layer 2: Pack

The Pack layer adds metadata to the encrypted payload:

- Message count
- Message type
- Timestamp
- Sender identity

Binary data (ciphertext + nonce + metadata) is serialized into a single `Uint8Array`. The library then signs this serialized data using the sender’s identity secret key (Isk), which can be verified with the identity public key (Ipk).

#### Layer 3: Seal

The Seal layer ensures only the recipient can read the full message:

- Combines the serialized package, the signature, and the sender’s Ipk into a single Uint8Array.
- Uses libsodium’s seal method to encrypt the data with the recipient’s encryption public key (Epk).
- The Epk is derived from the sender’s Ipk and can be publicly known; a separate key type is required for encryption versus signing.

### Session key exchange

Before messages can be fully encrypted, a session must be established using a triple X25519 Diffie-Hellman key exchange:

1. Session key generation: Each user generates a session keypair.
2. Initial Communication (IC): Sender transmits their session public key to the recipient. This message skips Layer 1 encryption but still applies Layers 2 and 3 for metadata and signature.
3. Response Communication (RC): Recipient generates their own session keypair and responds with their public key.
4. Key derivation: Each user combines their private session key with the received public key to derive tx and rx keys. These allow symmetric encryption where one user’s transmit key matches the other’s receive key.

This exchange can technically occur over an unencrypted channel, as the private keys never leave the users’ devices.

**Forward Security**: Every message uses a ratcheted key derived from the session keys and message count, ensuring each message has a unique encryption key.

**Backward Security**: Sessions can be rekeyed by repeating the key exchange. The library labels this as a session rekey, ensuring previous messages remain secure and unaffected while updating the session keys for future messages.

## Testing

We use [Jest](https://jestjs.io/) for testing. All tests can be found in the ```tests``` directory.

``` sh
# Run all tests
npm test

# Run individual test
npm test -- -t "Pattern match test name" 
```

## Build

We use [tsup](https://tsup.egoist.dev/) for building the package and triggered when we use pack.

``` sh
# Build and pack module
npm run pack
```

## Deployment

We use GitHub actions to handle the deployment process.

## Access the package namespace (GitHub packages)

Add the following namespace to your `.npmrc`

``` txt
@prismlabsdev:registry=https://npm.pkg.github.com
```

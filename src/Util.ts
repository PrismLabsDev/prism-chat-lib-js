import { type Sodium, sodiumReady } from "@/Sodium";
import type { KeyPair, SessionKeyPair, SymmetricEncryption } from "@/types";

// Generate signing public private key (ed25519)
export const createIdentityKeyPair = async (): Promise<KeyPair> => {
  const sodium: Sodium = await sodiumReady;
  const kp = sodium.crypto_sign_keypair();
  return {
    pk: kp.publicKey,
    sk: kp.privateKey
  };
}

// Convert public identity key to encrypt (ed25519 -> curve25519)
export const deriveIdentityEncryptionPublicKey = async (
  identityPublicKey: Uint8Array
): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.crypto_sign_ed25519_pk_to_curve25519(identityPublicKey);
}

// Convert private identity key to encrypt (ed25519 -> curve25519)
export const deriveIdentityEncryptionSecretKey = async (
  identitySecretKey: Uint8Array
): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.crypto_sign_ed25519_sk_to_curve25519(identitySecretKey);
}

// Generate session keypair for key exchange
export const createSessionKeyPair = async (): Promise<KeyPair> => {
  const sodium: Sodium = await sodiumReady;
  const kp = sodium.crypto_kx_keypair();
  return {
    pk: kp.publicKey,
    sk: kp.privateKey
  };
}

// Initial session keypair exhange for tx, rx
export const createSessionExchangeKeyPairSender = async (
  sessionPublicKey: Uint8Array,
  sessionSecretKey: Uint8Array,
  sessionPublicKey_peer: Uint8Array
): Promise<SessionKeyPair> => {
  const sodium: Sodium = await sodiumReady;
  const kp = sodium.crypto_kx_client_session_keys(
    sessionPublicKey,
    sessionSecretKey,
    sessionPublicKey_peer,
  );
  return {
    tx: kp.sharedTx,
    rx: kp.sharedRx
  };
}

// Response session keypair exhange for tx, rx
export const createSessionExchangeKeyPairRecipient = async (
  sessionPublicKey: Uint8Array,
  sessionSecretKey: Uint8Array,
  sessionPublicKey_peer: Uint8Array
): Promise<SessionKeyPair> => {
  const sodium: Sodium = await sodiumReady;
  const kp = sodium.crypto_kx_server_session_keys(
    sessionPublicKey,
    sessionSecretKey,
    sessionPublicKey_peer,
  );
  return {
    tx: kp.sharedTx,
    rx: kp.sharedRx
  };
}

// Ratchet a base key given a counter
export const ratchetKey = async (
  sessionTxRxKey: Uint8Array,
  count: number,
  ctx: string = "PRISMCHT"
): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.crypto_kdf_derive_from_key(
    32,
    count,
    ctx,
    sessionTxRxKey
  );
}

// Generate a key used for symmetric encrypt
export const createSymmetricKey = async (
  password: string | undefined = undefined,
  salt: Uint8Array | undefined = undefined,
  nonce: Uint8Array | undefined = undefined
): Promise<{
  key: Uint8Array
  nonce: Uint8Array,
  salt: Uint8Array
}> => {
  const sodium: Sodium = await sodiumReady;

  if (nonce === undefined) {
    nonce = sodium.randombytes_buf(24)
  }

  if (salt === undefined) {
    salt = sodium.randombytes_buf(16);
  }

  let key: Uint8Array;

  if (password) {
    key = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      sodium.from_string(password),
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    );
  } else {
    key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
  }

  return {
    key: key,
    nonce: nonce,
    salt: salt
  }
}

// Symmetric Encryption
export const symmetricEncrypt = async (
  data: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array | undefined = undefined,
  count: Uint8Array | undefined = undefined,
): Promise<SymmetricEncryption> => {
  const sodium: Sodium = await sodiumReady;

  if (count === undefined) {
    count = new Uint8Array(0)
  }

  if (nonce === undefined) {
    nonce = sodium.randombytes_buf(24);
  }

  const cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    data,
    count,
    null,
    nonce,
    key,
  );
  return {
    cipher: cipher,
    nonce: nonce,
    count: count
  }
}

// Decrypt Symmetric Encryption
export const symmetricDecrypt = async (
  cipher: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  count: Uint8Array | undefined = undefined,
): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;

  if (count === undefined) {
    count = new Uint8Array(0)
  }

  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    cipher,
    count,
    nonce,
    key
  );
}

// Generate a signature
export const sign = async (
  data: Uint8Array,
  identitySecretKey: Uint8Array
): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.crypto_sign_detached(data, identitySecretKey);
}

// Verify signature of data
export const verifySignature = async (
  signature: Uint8Array,
  data: Uint8Array,
  identityPublicKey: Uint8Array
): Promise<boolean> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.crypto_sign_verify_detached(
    signature,
    data,
    identityPublicKey
  )
}

// Encrypt data with recipients public key
export const publicEncrypt = async (
  data: Uint8Array,
  encryptPublicKey: Uint8Array
): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.crypto_box_seal(data, encryptPublicKey)
}

// Decrypt data encrypted with recipients public key
export const publicDecrypt = async (
  data: Uint8Array,
  encryptPublicKey: Uint8Array,
  encryptSecretKey: Uint8Array
): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.crypto_box_seal_open(
    data,
    encryptPublicKey,
    encryptSecretKey
  );
}

// Encode a number into little-endian byte array (arbitrary length, up to 255 bytes)
const encodeLength = (len: number): Uint8Array => {
  if (!Number.isSafeInteger(len) || len < 0) {
    throw new Error("Length must be a non-negative safe integer");
  }
  const bytes: number[] = [];
  let value = len;
  while (value > 0) {
    bytes.push(value & 0xff);
    value >>= 8;
  }
  if (bytes.length === 0) bytes.push(0); // handle 0-length
  if (bytes.length > 255) throw new Error("Length too large for 1-byte header");
  return new Uint8Array(bytes);
};

// Decode little-endian bytes into a number
const decodeLength = (bytes: Uint8Array): number => {
  let value = 0;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8) | bytes[i];
  }
  return value;
};

// Packs multiple Uint8Arrays with headers capped at 255 bytes
export const pack = (parts: Uint8Array[]): Uint8Array => {
  const totalLength = parts.reduce((sum, p) => {
    const lenBytes = encodeLength(p.length);
    return sum + 1 + lenBytes.length + p.length;
  }, 0);

  const packed = new Uint8Array(totalLength);
  let offset = 0;

  for (const p of parts) {
    const lenBytes = encodeLength(p.length);
    packed[offset++] = lenBytes.length;   // header size (1 byte)
    packed.set(lenBytes, offset);         // length bytes
    offset += lenBytes.length;
    packed.set(p, offset);                // data
    offset += p.length;
  }

  return packed;
};

// Unpacks packed Uint8Arrays with header size <= 255
export const unpack = (packed: Uint8Array): Uint8Array[] => {
  const parts: Uint8Array[] = [];
  let offset = 0;

  while (offset < packed.length) {
    const headerSize = packed[offset++];
    if (headerSize < 1 || headerSize > 255)
      throw new Error(`Invalid header size: ${headerSize}`);

    const lenBytes = packed.slice(offset, offset + headerSize);
    if (lenBytes.length !== headerSize)
      throw new Error(`Header truncated at offset ${offset}`);
    offset += headerSize;

    const len = decodeLength(lenBytes);
    if (offset + len > packed.length)
      throw new Error(`Invalid length (${len}) at offset ${offset}`);

    parts.push(packed.slice(offset, offset + len));
    offset += len;
  }

  return parts;
};

export const toBase64 = async (arr: Uint8Array): Promise<string> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.to_base64(
    arr,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
};

export const fromBase64 = async (str: string): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.from_base64(
    str,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
};

export const toString = async (arr: Uint8Array): Promise<string> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.to_string(arr);
};


export const fromString = async (str: string): Promise<Uint8Array> => {
  const sodium: Sodium = await sodiumReady;
  return sodium.from_string(str);
};


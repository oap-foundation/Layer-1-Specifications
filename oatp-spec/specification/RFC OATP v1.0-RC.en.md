# RFC: Open Agent Transport Protocol (OATP)
**Version:** 1.0 (PROPOSED STANDARD)
**Status:** CODE FREEZE
**Date:** 2025-11-25

**Section 1: Introduction**

## 1. Introduction

The *Open Agent Exchange Protocol (OAEP)* has laid the foundation for decentralized identity and trusted session keys (Layer 0). However, identity alone does not enable communication. In a world of mobile devices, unstable network connections, and increasing internet censorship, relying on the traditional client-server architecture of Web 2.0 is insufficient.

The **Open Agent Transport Protocol (OATP)** is the **Transport Layer (Layer 1)** of the OAP framework. It defines the standard for the asynchronous, encrypted, and fragmented exchange of data packets between agents. OATP decouples message delivery from physical network topology and replaces centralized data silos with a network of "blind" intermediaries (Blind Relays).

### 1.1 Purpose

The purpose of OATP is to provide a universal **logistics network** for digital messages. It functions as a "container ship" for all higher-level application protocols (such as OACP for commerce or SFP for social media).

OATP guarantees:
1.  **Confidentiality:** Content is end-to-end encrypted (based on OAEP keys).
2.  **Integrity:** Changes to message content are cryptographically detected.
3.  **Availability:** Messages reach the recipient even if they are offline at the time of sending ("Store-and-Forward").
4.  **Transport Agnosticism:** OATP defines the packet format and routing logic but is independent of the underlying transport channel (TCP, UDP, WebSocket, Bluetooth LE, or Sneaker-Net).

### 1.2 The Problem

Today's digital communication suffers from systemic deficits that OATP addresses:

*   **Metadata Surveillance (Metadata Leakage):**
    Centralized messengers (like WhatsApp or Telegram) often encrypt content but store metadata: *Who* communicates with *whom*, *when*, and *how often*? These traffic patterns are often more revealing than the content itself. OATP minimizes these traces through architectural design.

*   **Single Points of Failure & Control:**
    If the central server fails or the operator decides to block a user, communication halts. In the Web2 world, infrastructure dictates the ability to communicate.

*   **The "Offline Problem" in P2P Networks:**
    Pure peer-to-peer networks often fail due to the reality of mobile devices. Smartphones switch networks, enter power-saving modes, or lose signal. A direct synchronous connection is rarely permanently possible. Intermediate storage is needed, which traditionally requires trust in the storage provider.

### 1.3 Core Philosophy

OATP solves these problems through three radical design principles:

1.  **Blind Delivery:**
    The infrastructure (the Relay Servers) must know **nothing**. A relay does not know who the sender is and cannot read the content. It only knows that an encrypted data packet should be placed in a specific "mailbox" (identified by a pseudonymous hash). The network is "smart enough to deliver, but too dumb to spy".

2.  **Resilience via Sharding:**
    OATP does not rely on a single server. Messages are split into multiple fragments (**Shards**) using *Erasure Coding* (Reed-Solomon) and distributed across various independent relays.
    *   *Effect:* If a relay fails or is censored, the recipient can fully reconstruct the message from the remaining fragments. There is no longer a "Single Point of Failure".

3.  **Asynchronicity First:**
    The protocol assumes that sender and recipient are **not** online simultaneously. It is designed as a "Dead Drop" system. Agents drop messages into relays and pick them up when they have connectivity. Synchronous real-time communication is a special case, not the standard.

---

**Section 2: Terminology & Architecture**

## 2. Terminology and Architecture

OATP breaks with the classic client-server model where a server acts as a Trusted Third Party. Instead, it defines an architecture where the infrastructure is considered **untrusted**. To avoid misunderstandings, roles and components are defined normatively in this section.

The keywords "MUST", "MUST NOT", "SHOULD", and "MAY" are to be interpreted as described in RFC 2119.

### 2.1 Actors and Components

*   **Agent (Sender / Receiver):**
    A software endpoint (identified by a DID) that creates or receives OATP messages. Agents are the only entities in the system with access to private keys (from OAEP) and thus the only ones who can see message content in cleartext.
    *   *Sender:* The creator of the message. Responsible for encryption, fragmentation (sharding), and dispatch.
    *   *Receiver:* The recipient. Responsible for retrieval (Polling/Push), reconstruction, and decryption.

*   **Relay (Blind Relay):**
    A server node in the network that receives OATP packets, stores them temporarily, and delivers them upon request.
    *   **Blindness:** A relay MUST be designed as "blind". It knows neither the content (as it is encrypted) nor necessarily the identity of the sender. It acts as a "Dead Drop".
    *   **Untrusted:** The protocol assumes that relays can be compromised (Honest-but-Curious or malicious). Message security must not depend on relay integrity.

*   **Message Container (Envelope):**
    The complete, encrypted data unit before it is fragmented. It contains the payload (e.g., an OACP order) and metadata for the recipient (e.g., timestamp, signature).

*   **Shard (Fragment):**
    A segment of a Message Container generated by *Erasure Coding* (see Chapter 4). A single shard is useless and contains no readable information. Only the combination of a defined number of shards ($K$) enables the reconstruction of the container.

*   **Inbox (Mailbox):**
    A logical address on a relay. To protect metadata, the Inbox ID is NOT identical to the recipient's DID. It is a derived, rotating hash value (Blind Identifier) known only to the sender and recipient.

### 2.2 The OAP Layer Model

OATP operates as the middle layer in the OAP stack. It utilizes the underlying trust layer and transports the overlying application layer.

```text
+-------------------------------------------------------+
|  Layer 2: Application Layer (Payload)                 |
|  (OACP, SFP, OAPP, OACoP)                             |
|  -> Defines WHAT is communicated (JSON-LD)            |
+-------------------------------------------------------+
|                                                       |
|            E N C R Y P T I O N                        |
|                                                       |
+-------------------------------------------------------+
|  Layer 1: Transport Layer (OATP) - THIS RFC           |
|  -> Defines HOW it is transported                     |
|  -> Container Format, Sharding, Routing, Relays       |
+-------------------------------------------------------+
|                                                       |
|            A U T H E N T I C A T I O N                |
|                                                       |
+-------------------------------------------------------+
|  Layer 0: Trust Layer (OAEP)                          |
|  -> Defines WHO communicates (DIDs, Keys)             |
|  -> Handshake, Session Keys, Signatures               |
+-------------------------------------------------------+
```

1.  **Input:** OATP receives a JSON-LD object (e.g., `OrderRequest`) from Layer 2 and symmetric session keys (`sk_a_to_b`) from Layer 0.
2.  **Processing:** OATP packages the object, encrypts it (AEAD), splits it into shards, and distributes them to relays.
3.  **Output:** Physical HTTP/TCP packets to various IP addresses.

### 2.3 Architectural Concept: Distributed Resilience

OATP's architecture differs fundamentally from Email (SMTP) or Matrix. There is no "Home Server" where all a user's data resides.

*   **Receiver-Centric Routing:**
    The recipient's DID Document defines a list of *possible* relays (Service Endpoints). The sender selects a subset from this list.
*   **Erasure Coding (Redundancy):**
    Messages are encoded using an $(N, K)$ scheme.
    *   $N$: Total number of generated shards (e.g., 5).
    *   $K$: Minimum number of shards required for reconstruction (e.g., 3).
    *   **Resilience:** As long as $K$ relays are reachable and deliver data, the message arrives. Failure or censorship of $N-K$ relays (2 in the example) is mathematically compensated.
*   **Ephemeral Storage:**
    Relays are not databases for eternity. They buffer messages only temporarily ("Store-and-Forward") until the recipient picks them up (or a TTL expires). Long-term storage (History) is the responsibility of the agent's local database (Client-Side Storage).

---

**Section 3: The Message Container**

## 3. The Message Container

The **OATP Container** is the atomic unit of secure communication. It encapsulates the payload of the application layer (Layer 2, e.g., an OACP order) in a cryptographically protected shell.

This container is created and encrypted by the sender and then passed to the sharding layer (see Chapter 4). The recipient reconstructs this container from the shards and decrypts it.

**Design Decision:** To ensure maximum interoperability and security, the container format is based on **JWE (JSON Web Encryption, RFC 7516)** using *Compact Serialization*.

### 3.1 Container Structure

Since keys have already been negotiated via OAEP, sending an encrypted Content Encryption Key (Key Wrapping) is omitted. We use **Direct Encryption**.

#### 3.1.1 JWE Compact Serialization
The container consists of five parts separated by dots:
`Header.EncryptedKey.IV.Ciphertext.AuthenticationTag`

Since the `EncryptedKey` field is empty in Direct Encryption, the format is:
`BASE64URL(Header)..BASE64URL(IV).BASE64URL(Ciphertext).BASE64URL(Tag)`

#### 3.1.2 The Protected Header
The header contains metadata for routing, decryption, and replay protection. It is **integrity protected** (part of the AEAD calculation) but unreadable to the relay (due to sharding).

```json
{
  "alg": "dir",                      // Algorithm: Direct Encryption
  "enc": "C20P",                     // Encryption: ChaCha20-Poly1305 (per OAEP Suite)
  "kid": "a1b2c3d4...",              // Key ID: Session ID (Hash of OAEP transcript)
  "seq": 42,                         // OATP Message Sequence (for Nonce derivation & Anti-Replay)
  "zip": "DEF",                      // Optional: Compression (DEFLATE) before encryption
  "typ": "OATP+JSON"                 // Media Type
}
```

**Normative Field Definitions:**

*   **`alg` (Algorithm):** MUST be set to `dir`. This signals that the symmetric key is used directly (Shared Secret from OAEP).
*   **`enc` (Encryption Method):** MUST correspond to the Cipher Suite negotiated in the OAEP session (e.g., `C20P` for ChaCha20-Poly1305 or `A256GCM` for AES-GCM).
*   **`kid` (Key ID / Session ID):** This field identifies the active **OAEP Session**.
    *   *Value:* The first 16 bytes of the *Handshake Transcript Hash* ($H_T$) from OAEP v1.0 (Section 5.2).
    *   *Purpose:* Allows the recipient to find the correct decryption key in memory if multiple sessions are parallel (e.g., after re-keying).
*   **`seq` (Sequence Number):** A 64-bit Unsigned Integer incremented by the sender per session.
    *   *Purpose:* Used for detecting message loss, sorting, and replay protection.
    *   *Important:* This sequence number is logically bound to the OATP message and serves as **Input for HKDF-based Nonce Derivation** (see 3.3.3). It ensures that every message gets a unique nonce, even if they arrive "out-of-order".
*   **`typ` (Type):** MUST be set to `OATP+JSON`.

#### 3.1.3 Initialization Vector (IV / Nonce)
In the JWE string, the IV (nonce) is transmitted base64 encoded.
*   **Construction:** The sender MUST derive the nonce deterministically from the sequence number (`seq`) and the session key, as defined in Section 3.3.3.
*   **Validation:** The recipient MUST check if the nonce transmitted in the JWE string matches the `seq` contained in the header (by repeating the derivation locally). If not, the packet MUST be discarded.

### 3.2 The Payload

Before data is encrypted, the plaintext must be structured. The plaintext consists of two parts: The actual JSON-LD object and Traffic Padding.

#### 3.2.1 Plaintext Structure
The plaintext is a UTF-8 encoded JSON object:

```json
{
  "meta": {
    "created": "2026-10-12T10:00:00Z", // Timestamp (RFC 3339)
    "ttl": 86400,                       // Time-to-Live in seconds
    "type": "https://w3id.org/oacp/v1/OrderRequest" // Payload Type
  },
  "data": { ... },                      // The actual Layer-2 object
  "padding": "..."                      // Random bytes for length obfuscation
}
```

*   **`created`**: Used by the recipient to check if the message is stale (Replay Protection Window).
*   **`data`**: Contains the actual application object (e.g., OACP).

### 3.3 Encryption Process

Encryption transforms the plaintext (the JSON object) into ciphertext. OATP uses **AEAD** (Authenticated Encryption with Associated Data) to secure confidentiality and integrity simultaneously.

The process follows these four steps:

#### 3.3.1 Traffic Padding (Length Obfuscation)
Before encryption, the message length MUST be obfuscated to prevent inferences about content (side-channel attacks).
*   **Mechanism:** The sender adds cryptographically random bytes to the plaintext JSON in the `padding` field.
*   **Target Size:** The total size of the plaintext SHOULD be padded to the next multiple of **256 bytes** (or a power of two).
*   *Example:* A message of 150 bytes is padded with 106 bytes to reach 256 bytes.

#### 3.3.2 Key Selection
The sender selects the correct symmetric key from the active OAEP context.
*   If the sender is the **Initiator** of the session, it uses `Client_Write_Key`.
*   If the sender is the **Responder**, it uses `Server_Write_Key`.

#### 3.3.3 Nonce Derivation (HKDF-based)
The security of AEAD (especially ChaCha20-Poly1305) critically depends on the uniqueness of the Nonce (IV). Reuse leads to loss of confidentiality.

To exclude collisions with other protocols that might use the same OAEP session key and to enable "Out-of-Order" decryption, the Nonce MUST NOT simply be a padded counter. Instead, it MUST be derived deterministically via **HKDF-Expand** (according to RFC 5869) from the sequence number (`seq`).

**The Algorithm:**

1.  **Hash Function:** The same hash function defined in the active OAEP Cipher Suite MUST be used (e.g., **BLAKE3** for `OAEP-v1-2026`).
2.  **Inputs:**
    *   **PRK (Pseudo-Random Key):** The session key chosen for encryption (`Client_Write_Key` or `Server_Write_Key`).
    *   **Info (Context):** A concatenation of the ASCII string `"OATP-Nonce-v1"` and the 64-bit Big-Endian representation of the sequence number `seq` from the header.
    *   **L (Length):** 12 Bytes (96 Bit).
3.  **Operation:**
    `Nonce = HKDF-Expand(PRK, Info="OATP-Nonce-v1" || BigEndian(seq), L=12)`

**Example Construction:**
If `seq = 42` and hash is BLAKE3:
`Nonce = BLAKE3_KDF(Key, Context="OATP-Nonce-v1" + 0x000000000000002A)` (truncated to 12 bytes).

**Advantage:** This derivation makes the nonce statistically independent of the sequence number. This prevents correlation attacks and ensures OATP messages can be securely decrypted even if they arrive and are processed out of order by the recipient.

#### 3.3.4 AEAD Operation
Encryption follows the JWE standard (RFC 7516).

1.  **Input:**
    *   `K` (Key): The chosen Session Key.
    *   `IV` (Nonce): The derived 12-byte Nonce.
    *   `AAD` (Associated Data): The **Protected Header** (Base64URL encoded). This cryptographically binds metadata (`seq`, `kid`) to the ciphertext.
    *   `P` (Plaintext): The padded JSON object.
2.  **Operation:**
    `Ciphertext, Tag = ChaCha20_Poly1305_Encrypt(K, IV, AAD, P)`
3.  **Output:**
    The JWE Compact String is assembled from Header, IV, Ciphertext, and Tag.

### 3.4 Decryption Process

The recipient performs the following steps after receiving and reassembling the container:

1.  **Session Lookup:** Using `kid` in the header, the correct OAEP session and corresponding `Client_Write_Key` (or `Server_Write_Key`) is loaded.
2.  **Replay Check:** The `seq` in the header is checked against the local "Sliding Window". Already processed sequence numbers are discarded.
3.  **Nonce Reconstruction:** From the `seq` in the header and the known session key, the Nonce is locally recalculated via HKDF (see 3.3.3).
4.  **AEAD Decryption:**
    *   `Plaintext = AEAD_Decrypt(Key, Nonce, Header, Ciphertext, Tag)`
    *   If the integrity check (Tag Check) fails, the container MUST be discarded (`ERR_DECRYPT_FAILED`).
5.  **Time Check:** Is `meta.created + meta.ttl < now`? If yes -> Discard (Message expired).

### 3.5 Interaction with Sharding

It is important to emphasize: **The relay never sees this container as a whole.**
The container defined here is the input for the *Erasure Coding* process (Chapter 4). The relay only sees fragments (shards) that look statistically like random noise. Even if a relay could read a shard's header, it lacks the rest of the data and the key. The JWE container logically exists only on the endpoints (Sender/Receiver).

---

**Section 4: Sharding & Erasure Coding**

## 4. Sharding & Erasure Coding

The central design goal of OATP is resilience. In traditional systems, failure or censorship of the mail server leads to loss of communication capability. OATP eliminates this "Single Point of Failure" by applying **Erasure Coding** at the transport layer.

The encrypted *Message Container* defined in Chapter 3 is not transmitted as a whole. Instead, it is expanded into a set of $N$ fragments (**Shards**), of which any subset of $K$ shards is sufficient to fully reconstruct the message.

### 4.1 The Algorithm: Reed-Solomon

OATP mandates the use of **Reed-Solomon (RS) Codes**. To ensure different implementations (Rust, JavaScript, Python) produce compatible shards, parameters are strictly standardized in this section.

#### 4.1.1 Parameter Selection ($N, K$)
The sender determines parameters $N$ (Total number of shards) and $K$ (Shards needed for recovery) based on desired redundancy.

To ensure interoperability across all device classes and prevent abuse (Relay Flooding), the following **normative limits** apply:

1.  **Maximum Shards ($N_{max}$):** The total number $N$ MUST NOT exceed **16**.
    *   *Reasoning:* Limits overhead for relays and keeps Reed-Solomon decoding complexity low on low-power IoT devices.
2.  **Minimum Threshold ($K_{min}$):** The value $K$ MUST be at least **1**.
3.  **Redundancy Condition:** It MUST hold that: $1 \le K < N \le 16$.

**Recommended Standard Profile:**
For ordinary messages, the scheme **$(N=5, K=3)$** SHOULD be used.
*   *Efficiency:* Corresponds to 66% overhead.
*   *Resilience:* Up to 2 relays can fail, be censored, or corrupted without disrupting message flow (Failure Tolerance = 40%).

#### 4.1.2 Encoding Process
1.  The encrypted *Message Container* (see Ch. 3) is treated as the input blob.
2.  The blob is divided into $K$ equal-sized data blocks (padding with zeros if necessary, see 4.1.3).
3.  The RS encoder generates $N$ output blocks (Shards) from this.
4.  Each of these blocks forms the payload of an *OATP Shard Packet*.

#### 4.1.3 Normative Algorithm Specification (Reed-Solomon)
To guarantee bit-exact compatibility between different implementations, OATP v1.0 prescribes exact parameters for Erasure Coding mathematics. All implementations **MUST** adhere to the following standard:

1.  **Galois Field:** Operations take place in the finite field **$GF(2^8)$**. This enables direct processing of bytes (symbols from 0 to 255).
2.  **Generator Polynomial:** The irreducible polynomial **$p(x) = x^8 + x^4 + x^3 + x^2 + 1$** MUST be used.
    *   In hexadecimal notation, this corresponds to **`0x11D`** (decimal 285).
    *   *Note:* This is the de-facto standard (used in QR codes and CCSDS, among others), but differs from the AES polynomial (`0x11B`). Implementers must ensure their library uses `0x11D`.
3.  **Systematic Coding:** The encoder MUST work **systematically**.
    *   Meaning: The first $K$ generated shards (Index $0$ to $K-1$) are exact copies of the input data blocks.
    *   The remaining shards (Index $K$ to $N-1$) contain the calculated parity data.
4.  **Padding:** If the length of the encrypted *Message Container* (in bytes) is not divisible by $K$ without remainder, the input MUST be padded at the end with **Zero Bytes (`0x00`)** until the length is a multiple of $K$. This padding is automatically ignored/removed during decryption.

### 4.2 The Shard Packet Format

For the recipient to correctly reassemble fragments, each fragment requires metadata (Index, Total Number, Message ID).

**Security Mandate:** This metadata MUST be encrypted. The relay must not be able to correlate fragments.

#### 4.2.1 The Relay Envelope
The JSON object sent to the relay (via `POST /inbox`) contains exclusively information necessary for routing and storage management.

```json
{
  "inbox": "hmac_derived_hash_xyz",  // Target Address (Blind Inbox)
  "shard_id": "uuid-v4-random",      // Unique ID for DELETE operations
  "ttl": 604800,                     // Desired Time-To-Live (seconds)
  "data": "BASE64_ENCRYPTED_BLOB..." // Encrypted Shard Bundle
}
```

*   **`shard_id`**: A random UUIDv4. It MUST **not** be derived from content data to avoid deduplication leaks.
*   **`data`**: The ciphertext containing the actual information.

#### 4.2.2 The Shard Bundle (Content)
The `data` field in the Envelope is the result of AEAD encryption of the **Shard Bundle**. This inner object is visible only to the recipient.

```json
{
  "msg_id": "hash(container_iv)",   // ID of total message (for grouping)
  "idx": 0,                         // Index of this shard (0 to N-1)
  "total": 5,                       // Total number N
  "threshold": 3,                   // Required number K
  "payload": "BASE64_RS_CHUNK..."   // The raw Reed-Solomon fragment
}
```

#### 4.2.3 Shard Encryption
To transform the *Shard Bundle* into the `data` field of the Envelope, the sender uses the same symmetric key as for the message itself (from the OAEP session).

1.  **Nonce Formation:** To save overhead, the Nonce (IV) for shard encryption is derived deterministically from the `shard_id` of the outer envelope (e.g., the first 12 bytes of the SHA-256 hash of the UUID).
    *   *Advantage:* The relay cannot manipulate the `shard_id` without breaking decryption (Integrity Binding).
2.  **Operation:**
    `data = ChaCha20_Poly1305(Key, Nonce=Hash(shard_id), Plaintext=BundleJSON)`

**Security Gain:**
Since each shard packet has its own random `shard_id`, encryption produces completely different ciphertexts even for identical content (e.g., retries) or related fragments (`msg_id`). A relay cannot distinguish whether five shards belong to one message or five different messages.

### 4.3 Distribution Strategy

OATP security is based on the assumption that an attacker cannot control *all* relays simultaneously. Therefore, relay selection is critical.

#### 4.3.1 Relay Discovery
The sender consults the recipient's DID Document. The `service` section contains entries of type `OAPEndpoint`. These contain lists of Relay URLs.

#### 4.3.2 Diversity Routing
The sender MUST distribute the $N$ shards to minimize the probability of a *Common Mode Failure*.

1.  **Unique Relays:** Whenever possible, each shard SHOULD be sent to a different relay.
2.  **Topological Distance:** If the recipient lists relays in different jurisdictions or with different providers (AWS, Hetzner, Home Server), the sender SHOULD scatter shards across these groups.
3.  **Minimum Distribution:** The $N$ shards MUST be sent to at least $K$ physically separate relays (if available). Sending all shards to the same relay is FORBIDDEN (except in pure test environments), as this negates resilience.

### 4.4 Reassembly & Integrity

The process on the receiver side:

1.  **Polling/Push:** The recipient checks its (known) Blind Inboxes on relevant relays.
2.  **Collection:** It downloads all available shards.
3.  **Grouping:** Shards are grouped by `msg_id`.
4.  **Check:** Once $\ge K$ shards exist for a `msg_id`, reconstruction begins.
5.  **RS-Decode:** The Reed-Solomon algorithm reconstructs the original *Message Container*.
6.  **Integrity Check:**
    *   The recipient performs AEAD decryption (ChaCha20-Poly1305) on the reconstructed container.
    *   **Critical:** If the **Authentication Tag** of the container is invalid, it means at least one of the used shards was manipulated (corrupted).
7.  **Error Handling:**
    *   On integrity failure: If the recipient has more than $K$ shards (e.g., 4 of 5), it can try to identify and exclude corrupt shards through permutative trial (Brute Force of combinations).
    *   If reconstruction fails, the recipient sends (if possible) a negative acknowledge (NACK) via OATP or waits for timeout.

---

**Section 5: Relay Protocol**

## 5. The Relay Protocol (Server Interface)

An OATP Relay is a passive infrastructure node. Its sole task is to accept data blobs (shards), store them briefly, and deliver them to authorized collectors.

The Relay Protocol is specified as a **RESTful API** over **HTTPS**. Using TLS 1.3 is MANDATORY ("MUST") to ensure transport security.

### 5.1 Addressing: The Blind Inbox

Before the API can be used, the addressing scheme must be clarified. An OATP relay does not manage user accounts in the traditional sense. It manages temporary, pseudonymous storage locations: the **Blind Inboxes**.

To protect metadata, the Inbox ID MUST NOT allow inferences about the recipient's DID.

#### 5.1.1 Deterministic Derivation
Sender and recipient must agree on an Inbox ID. To avoid overhead, this is **deterministically derived from the OAEP session secret**.

*   **Base:** The *Shared Secret* ($S_{oaep}$) from the active OAEP session (see OAEP v1.0 Sec 5.5).
*   **Context:** The Relay URL (Canonical Origin per RFC 6454) to prevent the same Inbox ID being used on multiple relays (Cross-Relay Tracking).

**The Algorithm:**
Since the Inbox also serves for authentication during deletion (see 5.3), the ID is technically an **Ed25519 Public Key**.

1.  **Inbox Seed Derivation:**
    `Seed = HKDF(Salt=S_oaep, Info="OATP-Inbox-Derivation-" || Relay_URL, Length=32)`
2.  **Key Generation:**
    An ephemeral Ed25519 key pair is generated from the `Seed`:
    `Inbox_PrivKey, Inbox_PubKey = Ed25519_KeyGen(Seed)`
3.  **ID Format:**
    `inbox_id = HexEncode(Inbox_PubKey)` (32 Bytes / 64 Hex chars).

#### 5.1.2 Synchronization
*   **The Sender:** Calculates `inbox_id` locally before sending a shard. Requires no network interaction with the recipient.
*   **The Receiver:** Also calculates `inbox_id` for its known relays and polls them.
*   **Rotation:** Since the Inbox is bound to the OAEP Shared Secret, the Inbox ID rotates automatically as soon as the OAEP session is renewed (Re-Keying). This offers *Forward Secrecy* for addresses.

#### 5.1.3 Explicit Override (Optional)
In special cases (e.g., one-way communication or public drops), the recipient CAN provide the sender with an explicit, random `inbox_id` within the encrypted OAEP channel ("Reply-To" address). In this case, the explicit ID overrides the deterministic derivation.

#### 5.1.4 Inbox Rotation (Privacy Preservation)
Using a static `inbox_id` over long periods allows a global observer or relay operator to create communication patterns (Traffic Analysis). To prevent this, OATP defines mechanisms for regular rotation of the receiving address.

1.  **Implicit Rotation (Standard):**
    Since the deterministic Inbox ID is derived from the OAEP session secret (see 5.1.1), any renewal of OAEP keys (Session Rotation / Re-Keying) automatically leads to new Inbox IDs on all relays. Agents SHOULD therefore regularly perform an OAEP Re-Handshake (e.g., weekly or after $X$ messages).
2.  **Explicit Rotation (Override):**
    If an Inbox is compromised (e.g., flooded with spam) or the recipient desires immediate rotation without a full session reset, they CAN communicate an explicit new ID to the sender.
    *   This is done via an OATP message with payload type `https://w3id.org/oatp/v1/InboxUpdate`.
    *   Upon receipt and validation, the sender MUST update its local routing cache and send future shards to the new ID.
3.  **Grace Period:**
    To prevent loss of messages still "In-Flight" at the time of rotation or arriving late due to latency, recipients MUST continue monitoring the old Inbox for a transition period of **at least 7 days** after rotation. Only then may the private key of the old Inbox be deleted.

### 5.2 API Endpoints (Interface Definition)

An OATP-compliant relay MUST provide the following HTTP endpoints.

#### 5.2.1 Delivery
The sender (or another relay in the mesh) delivers a shard.

*   **Request:** `POST /v1/inbox/{inbox_id}`
*   **Header:**
    *   `Content-Type: application/json`
    *   `X-OATP-TTL`: Desired TTL in seconds (Server may limit this).
    *   `X-OATP-PoW`: (Conditional) A Hashcash token if the relay requires it under load or generally (Format see Section 5.6.2).
*   **Body:** The serialized Shard Envelope as JSON object (see Sec 4.2.1).
*   **Response:**
    *   `201 Created`: Shard successfully stored.
    *   `402 Payment Required`: (Optional) Relay is paid service (see OAPP Integration).
    *   `413 Payload Too Large`: Shard exceeds normative limit of **128 KB** (see 5.6.3).
    *   `429 Too Many Requests`: Rate limit for this IP or Inbox exceeded (Token Bucket empty, see 5.6.1).

#### 5.2.2 Retrieval
The recipient checks for new messages.

*   **Request:** `GET /v1/inbox/{inbox_id}`
*   **Parameter:**
    *   `?since={cursor}`: (Optional) Retrieve only messages after a specific timestamp/ID.
*   **Auth:** Requires Authentication (see 5.3).
*   **Response:**
    *   `200 OK`: JSON list of available shards (Metadata + Payload).
    *   `204 No Content`: Inbox is empty.

#### 5.2.3 Deletion (Acknowledgement)
After successful reconstruction, the recipient deletes the shards to free up storage ("Good Citizen Policy").

*   **Request:** `DELETE /v1/inbox/{inbox_id}`
*   **Parameter:**
    *   `?shard_id={uuid}`: Deletes specific shard.
*   **Auth:** Requires Authentication (see 5.3).
*   **Response:** `200 OK`.

### 5.3 Authentication at the Relay

Since relays are "blind", they do not know the OAEP identity (DID) of the recipient. How does the relay ensure only the authorized recipient can empty the Inbox?

OATP uses the concept of **Capability-Based Authorization** or cryptographic ownership.

**Mechanism: Inbox-as-Key**
1.  The `inbox_id` is technically a public key (Ed25519 Public Key) or a hash thereof.
2.  The recipient owns the corresponding private key (which they do *not* share with the sender; sender only knows Public ID).
3.  **Signed Requests:** For `GET` or `DELETE` requests, the recipient must sign the request (HTTP Method + Path + Timestamp) with the inbox's private key.
4.  **Validation:** The relay verifies signature against `inbox_id`. If valid, access is granted.

*Advantage:* The relay needs no user database. Authorization is mathematically encoded in the address itself.

### 5.4 Blind Storage Rules

Relays are designed as **"Untrusted Storage"**. To protect privacy and minimize operator liability, the following rules apply:

1.  **Opaque Data:** The relay MUST NOT attempt to parse or analyze the payload. It treats the body strictly as a byte stream.
2.  **No Indexing:** The relay MUST NOT create indices over metadata (like file size or timing) beyond what is necessary for operation.
3.  **Ephemeral Nature (TTL):**
    *   Every shard has a maximum Time-To-Live.
    *   Standard Retention: **14 Days**.
    *   After TTL expiration, the relay MUST irrevocably delete data (Garbage Collection). OATP is not an archive.
4.  **Size Limit:** To prevent abuse as a file-sharing platform, relays SHOULD enforce a hard limit on single shard size (normatively 128 KB, see 5.6.3). Larger files must be split into multiple shard sets at the application level.

### 5.5 Push Notifications (Wake-Up Mechanism)

Modern mobile operating systems (iOS, Android) aggressively terminate background connections to save power. Continuous polling (`GET`) is not reliably possible. OATP therefore defines mechanisms to "wake up" devices when new shards are available.

#### 5.5.1 The Privacy Dilemma
Centralized push services (Apple APNS, Google FCM) pose a privacy risk. Even if content is empty, operators learn via metadata (ping timing) *that* a user is receiving a message. Correlation with send time can reveal communication partners.

#### 5.5.2 Strategy A: UnifiedPush (Sovereign Standard)
For Android systems (and especially **Th!nkOS**), **UnifiedPush** is the preferred standard.
*   **Mandate:** Android-based OATP clients MUST support UnifiedPush.
*   **Function:** User chooses push provider (e.g., self-hosted **ntfy** server or relay operator). Google is completely removed from signal chain.
*   **Advantage:** Relay sends wake-up signal directly to user's chosen server. Metadata stays within trusted circle.

#### 5.5.3 Strategy B: Anonymized OS Pushes (APNS/FCM)
For iOS and standard Android, using OS services is unavoidable. OATP minimizes leaks via **"Content-Agnostic Pings"** and **Jitter**.

1.  **The "Empty Ping":**
    *   Relay sends push message containing **no user-specific data** in plaintext.
    *   Payload contains only command `OP: SYNC`. It contains **no** sender ID, **no** preview, and **no** specific Inbox ID (to prevent Apple/Google mapping Inboxes).
2.  **Local Processing:**
    *   OS wakes app (or extension) in background.
    *   App connects to *all* registered relays and polls for new shards.
    *   Only after successful download and local decryption does app generate visible notification for user.
3.  **Traffic Jitter (Delay):**
    *   To complicate timing analysis, relays SHOULD implement configurable, random delay (**Jitter**) between receiving shard and sending push (e.g., 0–30 seconds).
    *   *Note:* Trade-off between privacy (high jitter) and usability (real-time). User SHOULD be able to configure this.

#### 5.5.4 Separation of Relay and Push
For security, relays SHOULD NOT operate the push service themselves, but delegate to a dedicated **Push Gateway**.
*   Relay knows Inbox ID but not Push Token.
*   Push Gateway knows Token but not content or Inbox.
*   Prevents compromised relay from harvesting push tokens and deanonymizing users.

#### 5.5.5 Protocol between Relay and Push Gateway (Normative)
To preserve user privacy, relay **MUST NEVER** share `inbox_id` or shard metadata with Push Gateway. Relay only signals presence of new data for an abstract handle.

**Registration Flow (Client-side):**
1.  Client generates random, high-entropy string locally: `push_ref` (min 128 bit).
2.  Client registers `push_ref` along with OS Push Token at **Push Gateway**.
3.  Client registers `push_ref` along with Gateway URL at **Relay** (as inbox metadata).

**Notification (Relay -> Gateway):**
When shard arrives, relay performs `POST` request to Gateway.

*   **Payload:** JSON object MUST be minimized and allow no inferences about content.
    ```json
    {
      "ref": "random_string_generated_by_client", // The Mapping Handle
      "event": "SYNC",                            // Generic Trigger
      "ts": "2026-11-23T14:30:00Z"                // Timestamp against Replays
    }
    ```
*   **Privacy Mandate:** Relay **MUST NOT** transmit `inbox_id`, `shard_id`, shard size, or sender IP to Gateway.
*   **Gateway Behavior:** Gateway uses `ref` to lookup associated FCM/APNS token and sends empty "Wake-Up Ping" to OS. Does not log `ref` persistently.

### 5.6 Denial-of-Service (DoS) Mitigation

Since OATP relays are publicly accessible endpoints accepting data from anonymous senders, they are prime targets for flooding and resource exhaustion attacks. To ensure network availability, relays MUST implement the following protection mechanisms.

#### 5.6.1 Normative Rate-Limiting (Token Bucket)
Every relay MUST implement a **Token Bucket Filter** for incoming write access (`POST`).

*   **Algorithm:** One token removed per request. If bucket empty, request rejected with HTTP Status **`429 Too Many Requests`**.
*   **Scope:** Limit SHOULD be applied per `inbox_id`. For first message to new Inbox (where no traffic profile exists), limit CAN be applied per IP.
*   **Standard Parameters:**
    *   **Capacity (Burst):** **100 Tokens**. Allows immediate sending of approx. 20 messages (at $N=5$).
    *   **Refill Rate (Sustained):** **1 Token per second**.
*   **Implementation Note:** Relays MAY make these configurable but SHOULD never grant unlimited access.

#### 5.6.2 Proof-of-Work (Hashcash)
If relay is under high load or client exceeds rate limit, relay CAN dynamically request Proof of Work (PoW).

*   **Header:** Client must send `X-OATP-PoW` header in request.
*   **Algorithm:** OATP standardizes **Hashcash** (SHA-256).
*   **Format:** `1:<bits>:<timestamp>:<inbox_id>:<random_nonce>`
    *   `bits`: Required difficulty (number of leading zero bits).
    *   `timestamp`: UNIX Timestamp (validity window e.g. +/- 10 min).
    *   `inbox_id`: Binds PoW to target (prevents replay for other inboxes).
*   **Difficulty:**
    *   **Base:** 20 Bits (takes < 1 second on modern smartphones).
    *   **Escalation:** Relays CAN increase difficulty under load.
*   **Validation:** `SHA256(HeaderString)` must be `< 2^(256-bits)`.

#### 5.6.3 Shard Size Limit
To prevent memory exhaustion attacks where attackers send huge JSON objects to crash server parser, a hard limit applies.

*   **Mandate:** Maximum HTTP Body size for `POST /inbox` (including JSON overheads and Base64 encoding) is normatively limited to **128 KB** (131,072 bytes).
*   **Consequence:** Larger data packets MUST be split by sender at Layer 2 (before OATP packaging) into multiple OATP messages ("Application Layer Chunking"). Requests exceeding limit MUST be rejected by relay with **`413 Payload Too Large`**, ideally before full body is read (Streaming Check).

---

**Section 6: Delivery Reliability**

## 6. Delivery Reliability

Since OATP is based on a "Best Effort" network of untrusted relays and fragmented data packets, confirming successful delivery is non-trivial. OATP implements reliability not at the transport level (TCP ACKs are insufficient) but at the **End-to-End level**.

### 6.1 Acknowledgements

OATP distinguishes strictly between **Transport Acknowledgements** (Server received data) and **Protocol Acknowledgements** (Agent processed data).

#### 6.1.1 Relay Response (Hop-by-Hop)
When sender drops shard at relay, it receives HTTP status code (e.g. `201 Created`).
*   **Meaning:** "Relay has stored shard."
*   **Limit:** Guarantees NEITHER that recipient can pick up shard NOR that relay is honest. Serves only for upload retry handling.

#### 6.1.2 Delivery Receipt (End-to-End)
The only reliable confirmation is the **Delivery Receipt** from recipient agent.
*   **Trigger:** Once recipient has collected enough shards ($K$), successfully reconstructed container (Reed-Solomon Decode), and verified cryptographic integrity (AEAD Tag), it MUST generate receipt.
*   **Format:** Receipt is technically a new, very small OATP message sent back to sender.
*   **Content:**
    ```json
    {
      "type": "https://w3id.org/oatp/v1/DeliveryReceipt",
      "ack_for_seq": 42,       // Sequence number of received message
      "timestamp": "2026-11-23T14:35:00Z"
    }
    ```
*   **Security:** Receipt MUST be encrypted and signed like any other message. Proves to sender that recipient holds private key and could read message.

**Distinction:** A `DeliveryReceipt` confirms **technical delivery**. It is NOT a "Read Receipt" on UI level. Whether user saw message is handled at Layer 2 (e.g. Messenger Protocol).

### 6.2 Retry Logic

What if no receipt arrives? OATP defines strategies to avoid network spam yet ensure delivery.

#### 6.2.1 Timer-based Retry
Sender starts timer after sending all shards (e.g. `ExpectedLatency * 2`). If expired without receipt, sender enters retry mode.

#### 6.2.2 Exponential Backoff
To avoid flooding network, senders MUST apply exponential backoff for failed delivery attempts (e.g. retry after 1 min, 5 min, 15 min, 1 hour).

#### 6.2.3 Relay Rotation
Pointless to keep sending same shards to same (possibly censoring or failed) relay.
*   **Strategy:** On retry, sender SHOULD choose alternative relays from recipient's DID Document if available.

### 6.3 Adaptive Redundancy (Incremental Repair)
Special advantage of Erasure Coding is incremental repair.
Scenario: Sender sent 5 shards ($N=5, K=3$). Recipient received only 2 (one too few).

*   **Inefficient:** Sender resends all 5 shards.
*   **OATP Way (Smart Repair):** Sender generates **new** shards from original container (e.g. Index 6 and 7). Sends only these additional parity fragments.
    *   *Advantage:* Recipient can combine existing 2 shards with new shard to reach $K=3$. Bandwidth saved.

### 6.4 Duplicate Handling and Replay Protection

Due to asynchronous network nature, sender retry logic, and potential attacks, it is unavoidable that recipient receives same data multiple times. OATP defines two-stage process to efficiently discard duplicates and prevent replay attacks.

#### 6.4.1 Stage 1: Shard Deduplication
Recipients MUST filter incoming shards by unique ID before storage.
*   **Identifier:** Combination of `msg_id` and `idx` (Index) from decrypted *Shard Bundle*.
*   **Check:** If shard with same index exists for not-yet-reconstructed message, duplicate MUST be discarded. Saves staging storage.

#### 6.4.2 Stage 2: Message Replay Cache (Normative)
To prevent attacker from resending old, valid shards (before TTL expiry) to trigger application (e.g. double order), recipients MUST maintain persistent **Replay Cache**.

*   **Content:** Cache stores `msg_id` (Hash of container IV) of all successfully processed messages.
*   **Timing of Check:** Check against cache MUST occur **after** decryption of Shard Bundle (cheap) but mandatorily **before** Reed-Solomon reconstruction (expensive).
    *   *Rule:* If `msg_id` of incoming shard exists in Replay Cache, entire processing for this shard MUST be aborted. Not stored, no RS-Decode triggered.
*   **Reaction (Idempotency):** Although message discarded, duplicate often indicates original *Delivery Receipt* was lost (triggering sender retry). Recipient SHOULD therefore (with rate-limiting) resend `DeliveryReceipt` for this `msg_id` without passing message to Layer 2 again.

#### 6.4.3 Retention Policy
Replay Cache cannot grow infinitely. Entries can be safely deleted if message would be invalid anyway due to age.
*   **Expiry:** `Expiry = created_timestamp + ttl` (from container metadata).
*   **Cleanup:** Entries in Replay Cache MUST be kept at least until expiry reached. Shards arriving after this date are discarded by time check in Sec 3.4, so cache entry no longer needed.

---

**Section 7: Security Considerations**

## 7. Security Considerations

OATP operates in an environment where transport infrastructure (Relays) is considered **untrusted**. Security model must guarantee that even malicious or compromised relay can neither read content nor effectively censor or deanonymize communication.

### 7.1 Metadata Protection and Traffic Analysis

While content encryption (Chap 3) is considered solved, metadata ("Who speaks with whom?") represents largest attack surface. OATP minimizes this surface but cannot fully eliminate it at protocol level.

#### 7.1.1 IP Exposure and Transport
*   **Problem:** Every relay needs sender IP (on `POST`) and recipient IP (on `GET`) at TCP/IP level to establish connection. Global Passive Adversary or collusive relay network could use timing correlations to link sender and recipient.
*   **Mitigation:**
    *   **Blind Inboxes:** Since Inbox IDs are random hashes, not DIDs, relay cannot trivially map IP to digital identity unless DID leaked otherwise.
    *   **Transport Obfuscation:** Agents with high protection needs MUST tunnel relay access via anonymization networks (Tor, I2P) or VPN chains. OATP implementations SHOULD offer native SOCKS5 proxy support.

#### 7.1.2 Timing Attacks & Correlation
*   **Problem:** If Agent A sends shard and Agent B retrieves it milliseconds later, temporal pattern emerges.
*   **Mitigation (Asynchronicity):** OATP designed as asynchronous protocol. Recipients SHOULD randomize retrieval intervals (Jitter) or use constant retrieval rates to complicate correlations. Immediate delivery via Push ("Wake-Up Ping") is trade-off between latency and privacy.

#### 7.1.3 Padding (Size Correlation)
*   **Mandate:** All shards and containers MUST be padded to standardized block sizes (see 3.3.1). Relay must not distinguish whether shard is part of short text or large image.

### 7.2 Spam & Denial-of-Service (DoS) Mitigation

Public, anonymous drop boxes (Blind Inboxes) are attractive for spam and flooding attacks. OATP implements economic and cryptographic hurdles ("Backpressure").

#### 7.2.1 Infrastructure Protection (Relay Level)
To secure relay availability, mechanisms defined in **Section 5.6** are used:
*   **Rate Limiting:** Normative Token Bucket prevents single senders overloading relay.
*   **Proof-of-Work:** Hashcash header (`X-OATP-PoW`) makes spam computationally expensive.
*   **Size Limits:** 128 KB per shard limit prevents Memory Exhaustion attacks.

#### 7.2.2 Inbox Rotation (Recipient Level)
*   **Secret Inbox ID:** `inbox_id` is a secret (Capability). Those who don't know ID cannot drop anything.
*   **Rotation:** If Inbox "burned" (e.g. spam flooded despite relay protection), recipient generates new ID and shares with legitimate contacts via OAEP (see 5.1.4). Old inbox deleted or ignored at relay.

### 7.3 Forward Secrecy & Key Management

OATP security directly depends on OAEP key security.

*   **PFS Inheritance:** Since OATP uses `Session Keys` from OAEP handshake (using Ephemeral Diffie-Hellman), OATP inherits **Perfect Forward Secrecy** per **OAEP v1.0**. If device seized later, recorded old OATP shards cannot be decrypted as session keys deleted.
*   **Deletion Mandate:**
    *   **Sender:** MUST remove plaintext and encrypted container from memory immediately after sharding.
    *   **Recipient:** MUST irrevocably delete received shards once container successfully reconstructed.
    *   **Relay:** MUST physically delete shards after TTL expiry or explicit `DELETE` command.

### 7.4 Unreadability of Fragments

Single shard (or set of $K-1$ shards) contains theoretically and practically **zero information** about message content.
*   **Encryption:** Since shard metadata (`msg_id`, `idx`) are AEAD encrypted per Sec 4.2.3, attacker compromising relay sees only uniform random data.
*   **Censorship Resistance:** Relay cannot selectively block fragments of specific messages or senders as no distinguishing features exist ("All or Nothing").

### 7.5 Integrity of Fragments (Shard Corruption Detection)

Malicious relay could try to manipulate stored shards (Bit-Flip) to prevent message reconstruction at recipient ("Pollution Attack"). OATP v1.0 counters risk via multi-stage integrity check.

1.  **Primary Check (Shard Level):**
    Since *Shard Bundle* encrypted with AEAD (ChaCha20-Poly1305) per Sec 4.2.3, every single shard possesses cryptographic **Authentication Tag**.
    *   **Mandate:** Recipients MUST validate Auth-Tag when decrypting `data` field in Relay Envelope.
    *   **Consequence:** If validation fails, shard manipulated or damaged. Shard MUST be discarded immediately and MUST NOT enter Reed-Solomon process.

2.  **Secondary Check (Container Level):**
    Should shard be technically validly decrypted but contain logically inconsistent data (e.g. sender error), integrity check of reconstructed JWE container (see 3.4) catches it. If AEAD Tag mismatch, reconstruction failed.

3.  **Blacklisting (Reputation):**
    Relay delivering shard with invalid AEAD Tag has either storage error or acts maliciously. Clients SHOULD temporarily blacklist such relays to avoid wasting bandwidth on unreliable nodes.
    
---

**Section 8: Implementation Guidelines**

## 8. Implementation Guidelines

Implementing OATP, especially on mobile devices, requires careful resource management. A "naive" design opening separate TCP connection for every shard would drain smartphone battery rapidly and lead to poor User Experience.

This chapter defines Best Practices and architectural patterns recommended for production-ready OATP library (SDK).

### 8.1 Batching & Network Efficiency

Sending single message in standard scheme $(N=5)$ generates 5 outbound HTTP requests. To minimize overhead (TLS Handshake, Headers), implementations SHOULD use batching strategies.

#### 8.1.1 Outgoing Batching (Nagle's Algorithm for Shards)
If agent sends multiple messages in short succession (e.g. chat messages) or large file (split into many shards):
*   **Strategy:** OATP Client SHOULD collect outgoing shards addressed to *same* relay in queue for short window (e.g. 50-200ms).
*   **Bulk API:** Relays MUST offer endpoint for batch operations (e.g. `POST /v1/batch/inbox`) accepting array of shards in single request.
*   **Advantage:** Reduction of RTT (Round Trip Time) and CPU load on both sides.

#### 8.1.2 Parallelism in Download
Latency is critical factor in reception.
*   **Parallel Fetch:** Recipient SHOULD try downloading shards from different relays in parallel.
*   **Racing:** Once $K$ shards successfully loaded, reconstruction attempt SHOULD start. Ongoing downloads of remaining $N-K$ shards CAN be aborted once container integrity verified to save bandwidth.

### 8.2 Offline Handling & The "Local Outbox"

OATP is a "Store-and-Forward" protocol. Network layer must assume device is offline at time of sending.

#### 8.2.1 Persistent Queue
Implementations MUST NOT hold messages only in RAM.
1.  **Persistence:** Before send attempt, encrypted container and its shards MUST be written to local persistent database (e.g. SQLite, LevelDB).
2.  **State Management:** Each shard in Outbox has status (`PENDING`, `SENT`, `FAILED`).
3.  **Background Sync:** Background Worker (e.g. Android WorkManager, iOS BackgroundTasks) processes queue once connectivity exists.

#### 8.2.2 Intelligent Retry (Backoff)
If relay unreachable:
*   **No Busy-Loop:** No immediate, continuous retry allowed.
*   **Exponential Backoff:** Wait time between attempts must increase exponentially (1s, 2s, 4s, 8s...) to save battery and not overload server.
*   **Circuit Breaker:** If relay consistently returns errors (e.g. 5xx codes), it SHOULD be temporarily put on internal "Sick List" and avoided for new messages (see Relay Rotation in 6.2.3).

### 8.3 Push Notifications (The "Wake-Up" Problem)

On modern mobile OS (iOS, Android), apps cannot hold permanent background connections. They are "frozen" by OS. External trigger needed to receive messages in real-time.

Since OATP relays don't know content, they cannot send "Rich Notifications" (with text preview). This is a feature, not a bug ("Privacy by Design").

#### 8.3.1 The "Empty Ping" Flow
1.  **Registration:** Recipient agent registers with OS push service (APNS/FCM) and deposits token at relay (indirectly via Gateway Protocol, see 5.5.5).
2.  **Signal:** Shard arrives, relay sends only signal: "New data for Handle X". Signal contains **no** payload.
3.  **Wake-Up (iOS Notification Service Extension):**
    *   On iOS, app uses *Notification Service Extension*.
    *   OS wakes extension for short time (approx 30 sec) in background.
    *   Extension connects to relay, downloads shards, reconstructs and decrypts container.
4.  **Local Display:** Only *after* local decryption does app generate visible notification ("New message from Anna: Hello!").
5.  **Advantage:** Apple/Google see only *that* notification came, but never content or sender.

#### 8.3.2 UnifiedPush (Android Alternative)
For Android users without Google Play Services (e.g. Th!nkOS, GrapheneOS), library SHOULD support open standard **UnifiedPush**. Enables use of self-hosted push servers (e.g. ntfy), removing Google FCM dependency entirely.

### 8.4 Storage Management & Garbage Collection

Since OATP clients must cache data fragments (shards) locally – both incoming (for reconstruction) and outgoing (for retries) – storage requirements grow dynamically. Without strict management, attacker could fill device storage by sending incomplete fragment sets.

#### 8.4.1 Ephemeral Inbound Storage
Incoming shards are means to an end.
*   **Immediate Cleanup:** Once $K$ shards received and Message Container successfully reconstructed and validated (AEAD Tag Check), ALL shards belonging to this `msg_id` MUST be **immediately** physically deleted from storage.
*   **Deduplication:** Shard arriving for `msg_id` where message already reconstructed MUST be discarded.

#### 8.4.2 The "Orphan" Problem (Adaptive Garbage Collection)
Attacker could target recipient with incomplete shard sets (e.g. always only $K-1$). Fragments never reconstructable but occupy staging storage. Pure static timeout would allow attacker to permanently block device storage ("Storage Exhaustion DoS").

To prevent this, implementations MUST realize **Adaptive Garbage Collection** based on fill level of assigned storage (Quota):

1.  **Base Timeout (Normal Op):** As long as storage usage below threshold (Recommendation: **80%**), standard timeout `MAX_REASSEMBLY_TIME` of **24 Hours** applies.
2.  **Aggressive Cleanup (High Load):** Usage above 80%, timeout for *new and existing* incomplete sets MUST be drastically reduced (Recommendation: **1 Hour**). Forces attacker to massively increase attack rate, detectable by rate limiting.
3.  **Panic Mode (Critical):** Usage above critical value (Recommendation: **95%**), system MUST switch to **LRU Mode (Least Recently Used)**. Oldest incomplete fragment sets deleted immediately to make space for new data, regardless of age.
4.  **Concurrency Limit:** Additionally, number of simultaneously open, incomplete messages per `inbox_id` SHOULD be limited (e.g. max 50 pending messages).

#### 8.4.3 Outbox Management
Sent messages must be kept for potential retries (see 6.2).
*   **Delete Trigger:** Shards MUST NOT be deleted from local DB until:
    1.  Cryptographically valid **Delivery Receipt** (6.1.2) from recipient arrived.
    2.  OR user manually deletes message.
    3.  OR global `MESSAGE_EXPIRY_TIMEOUT` (e.g. 14 Days) exceeded.

#### 8.4.4 Storage Quotas & Eviction
To ensure OS stability, OATP libraries SHOULD respect storage limit (Quota).
*   **LRU Eviction:** If storage tight, client SHOULD prematurely delete oldest, incomplete fragment sets ("Orphans").
*   **Prioritization:** Outbox (own sent messages) SHOULD have higher priority for retention than Inbound Staging Area.

### 8.5 Interoperability in Code (SDK Design)

OAP SDK should encapsulate complexity of Erasure Coding and Networking.

*   **Recommended Abstraction:** Layer 2 developers should call only one method:
    `messenger.send(recipient_did, payload_json)`
*   **Under the Hood:** SDK autonomously handles:
    1.  OAEP Handshake / Session Lookup.
    2.  JWE Encryption.
    3.  Reed-Solomon Encoding.
    4.  Relay Selection and Upload.
    5.  Retry Management.
*   **Events:** SDK should emit events (`onProgress`, `onDelivered`, `onRead`) so UI (e.g. ticks in chat) can update reactively.

### 8.6 Strategy for Multiple Devices (Multi-Device Strategy)

Users often use multiple devices (e.g. Smartphone and Laptop) in parallel. Since OATP has no central "Sync Server", message sync must be solved architecturally.

#### 8.6.1 The "Shared Inbox" Anti-Pattern
It is STRONGLY advised against using same `inbox_id` on multiple devices simultaneously.
*   **Race Condition:** If Device A retrieves messages and deletes per protocol (`DELETE`), data irrevocably lost for Device B before it could sync.
*   **State Conflicts:** Managing Nonce Caches and Replay Protection becomes extremely complex and error-prone with shared inboxes.

#### 8.6.2 Device-Specific Inboxes (Recommended)
Correct strategy in OATP v1.0 is using dedicated inboxes per device.
1.  **Registration:** Each user device registers own Service Endpoint in shared DID Document (e.g. `#mobile-inbox` and `#desktop-inbox`).
2.  **Sender Behavior (Client-Side Fan-Out):**
    Sender analyzes recipient DID Document. If multiple valid `OAPEndpoint` entries found, MUST send message (or shards) to **all** these endpoints.
    *   *Note:* Increases traffic for sender linearly with number of recipient devices, but guarantees reliable delivery without server logic.
3.  **Independence:** Each recipient device manages own retrieval and deletion cycle fully autonomously.

### 8.7 Flow Control (Informative)

In OATP v1.0, no protocol-internal, normative mechanism for **End-to-End Flow Control** (e.g. Sliding Windows for Backpressure signaling between agents) exists yet. This is planned feature for OATP v1.1.

To avoid resource exhaustion in asymmetric connections (e.g. Desktop sends to IoT device) in v1.0, following guidelines apply:

1.  **Transport Layer Backpressure:** Senders MUST strictly react to HTTP status codes from relays. `429 Too Many Requests` or `507 Insufficient Storage` is hard signal to throttle send rate immediately.
2.  **Application Layer Throttling:** Application Layer (Layer 2) must not treat OATP as "Firehose". Implementations SHOULD internally limit number of **"In-Flight" messages** (sent but no *Delivery Receipt* yet) per recipient (Recommendation: max 50 unconfirmed messages). If limit reached, `send()` call should block or fail.
3.  **Emergency Brake:** Recipients flooded by sender CAN temporarily silently drop further messages from this sender (Silent Drop) or – as ultima ratio – rotate `inbox_id` to physically interrupt data stream.

---

**Section 9: Appendix & Examples**

## 9. Appendix and Examples

This section is informative. It provides examples of message lifecycle, JSON payloads, and formal API definition.

### 9.1 End-to-End Message Flow (Example)

Scenario: Alice (Sender) sends OACP Order to Bob (Recipient).
*   **OAEP Status:** `ACTIVE`. Session Keys (`Client_Write_Key`) negotiated.
*   **Sharding Parameters:** $N=5, K=3$.
*   **Sequence:** This is 42nd message in session (`seq = 42`).

#### Step 1: Payload Creation
Alice creates JSON-LD object (Layer 2).
```json
// Plaintext
{
  "meta": {
    "type": "https://w3id.org/oacp/v1/OrderRequest",
    "created": "2026-11-23T14:30:00Z",
    "ttl": 86400
  },
  "data": { "offerId": "uuid-123", "product": "Th!nkPhone" },
  "padding": "a8f3... (random bytes to block size 256)"
}
```

#### Step 2: Encryption (Containerization)
Alice prepares JWE Header and derives Nonce.

1.  **Header:** `{"alg":"dir", "enc":"C20P", "seq":42, "kid":"a1b2c3d4..."}`.
2.  **Nonce Derivation:** Alice calculates Nonce via HKDF (see 3.3.3):
    `Nonce = HKDF(Key, Info="OATP-Nonce-v1" || 0x000000000000002A, L=12)`.
3.  **Encryption:** Encrypts plaintext with `ChaCha20-Poly1305` using derived IV.
4.  **Result:** JWE Compact String.
    `eyJhbGciOiJkaXIiLCJlbmMiOiJDMjBQ... (Header)..ivBase64.ciphertextBase64.tagBase64`

#### Step 3: Sharding (Erasure Coding)
Encrypted container (say 1000 bytes) padded (to multiple of $K=3$, i.e. 1002 bytes) and split into 3 Data Chunks. Reed-Solomon Encoder (GF(2^8), Polynomial 0x11D) generates 2 additional Parity Chunks.
*   **Result:** 5 Shards.

#### Step 4: Distribution
Alice packages each shard in encrypted Relay Envelope (incl. `shard_id` and encrypted `msg_id`) and sends to 5 different relays (R1 to R5).
*   `POST https://relay1.com/v1/inbox/{blind_hash_1}` -> Body: Shard 1 Envelope
*   ...

#### Step 5: Reception & Reconstruction
Bob polls relays.
1.  Downloads Shard 1, 3, and 5 successfully.
2.  Since $3 \ge K$, starts RS-Decode and gets JWE Container back.
3.  Reads `seq=42` from header, derives same Nonce locally via HKDF.
4.  Checks Auth Tag (Integrity OK) and decrypts Payload.
5.  Sends `DeliveryReceipt` for `seq=42` back.

### 9.2 JSON Schemas (Relay API)

For Relay Server interoperability, here is **OpenAPI 3.0 (Swagger)** definition of interface.

```yaml
openapi: 3.0.0
info:
  title: OATP Relay API
  version: 1.0.0
  description: API definition for OATP Blind Relays (Layer 1)
paths:
  /v1/inbox/{inbox_id}:
    post:
      summary: Deliver a shard (Drop)
      parameters:
        - name: inbox_id
          in: path
          required: true
          schema:
            type: string
            format: hex
            minLength: 64
        - name: X-OATP-TTL
          in: header
          description: Requested Time-To-Live in seconds
          schema:
            type: integer
        - name: X-OATP-PoW
          in: header
          description: Hashcash Proof-of-Work (if required by relay)
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ShardEnvelope'
      responses:
        '201':
          description: Shard stored successfully
        '402':
          description: Payment Required (OAPP integration needed)
        '413':
          description: Payload too large (Exceeds 128KB limit)
        '429':
          description: Too Many Requests (Token Bucket exhausted)
    get:
      summary: Retrieve shards (Pickup)
      security:
        - BearerAuth: [] # Signature over request using inbox private key
      parameters:
        - name: inbox_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: List of available shard envelopes
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ShardEnvelope'
        '204':
          description: No Content (Inbox empty)
    delete:
      summary: Delete shards (Cleanup)
      security:
        - BearerAuth: []
      parameters:
        - name: inbox_id
          in: path
          required: true
          schema:
            type: string
        - name: shard_id
          in: query
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Shard deleted

components:
  schemas:
    ShardEnvelope:
      type: object
      required: [inbox, shard_id, ttl, data]
      properties:
        inbox:
          type: string
          description: The blind inbox ID (must match path)
        shard_id:
          type: string
          format: uuid
          description: Unique random ID for this shard (for DELETE)
        ttl:
          type: integer
          description: Retention time in seconds
        data:
          type: string
          format: byte
          description: Base64 encoded, AEAD-encrypted Shard Bundle (opaque to relay)
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      description: Ed25519 Signature of the request
```

### 9.3 Cryptographic Test Vectors

Implementers MUST test their sharding logic against these vectors to ensure Reed-Solomon implementation is binary compatible.

#### 9.3.1 Reed-Solomon (N=5, K=3)
*   **Algorithm:** Reed-Solomon over GF(2^8) with Polynomial `0x11D` (Vandermonde Matrix).
*   **Input Data:** `48656c6c6f20576f726c6421` ("Hello World!")
    *   *Note:* Input (12 Bytes) already divisible by 3, no padding needed.
*   **Expected Shards (Hex):**
    *   Shard 0 (Data): `48 65 6c 6c` ("Hell")
    *   Shard 1 (Data): `6f 20 57 6f` ("o Wo")
    *   Shard 2 (Data): `72 6c 64 21` ("rld!")
    *   Shard 3 (Parity): `55 bf 5f 22`
    *   Shard 4 (Parity): `e7 9a 31 d9`

*Test Scenario:* Delete Shard 0 and 1. Feed Shard 2, 3, and 4 into decoder. Result MUST be exactly `48656c6c6f20576f726c6421`.

### 9.4 Reference Implementation

Official reference implementation of OAP Foundation is in repository `oap-core-rs`.

*   **Crate:** `oatp::core`
*   **Modules:**
    *   `oatp::crypto::aead` (Encryption & HKDF)
    *   `oatp::coding::erasure` (Sharding Logic with GF(2^8))
    *   `oatp::transport::relay` (HTTP Client/Server Stubs)

Developers urged to use this Rust library (or its bindings for Kotlin/Swift/JS) for critical applications instead of implementing Sharding Algorithm themselves.
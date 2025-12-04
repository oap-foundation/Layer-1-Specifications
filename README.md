# OAP Layer 1: Transport & Logistics

[![Spec Status](https://img.shields.io/badge/status-CODE%20FREEZE-snowflake)](./RFC%20OATP%20v1.0-RC.en.md)
[![Protocol](https://img.shields.io/badge/protocol-OATP-orange)](./RFC%20OATP%20v1.0-RC.en.md)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-green)](LICENSE)

> **The Logistics Network of the Agent Economy.**
>
> This repository contains the normative specifications for **Layer 1** of the Open Agent Protocol (OAP) framework. While Layer 0 handles *Trust*, Layer 1 handles the physical movement of data packets in an asynchronous, censorship-resistant, and privacy-preserving manner.

## 📦 Scope of Layer 1

Layer 1 acts as the "Shipping Container" standard for the decentralized web. It decouples the sender from the receiver physically and temporally.
1.  **Asynchronous:** Agents do not need to be online at the same time ("Store-and-Forward").
2.  **Resilient:** Messages survive network partitions and relay failures via Erasure Coding.
3.  **Blind:** The infrastructure (Relays) knows neither the sender, the content, nor the true identity of the receiver.

### Primary Specifications

| Acronym | Protocol Name | Version | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| **OATP** | **Open Agent Transport Protocol** | `1.0-RC` | ❄️ Freeze | The standard for encryption, sharding, routing, and the "Blind Relay" API. |

👉 **[READ THE OATP SPECIFICATION](./RFC%20OATP%20v1.0-RC.en.md)**

## ⚡ Key Technologies

Layer 1 mandates specific mechanisms to ensure a "Zero-Trust" infrastructure model:

### 1. The Message Container (JWE)
All application payloads (from Layer 2) are wrapped in **JSON Web Encryption (JWE)** containers.
*   **Encryption:** Uses **ChaCha20-Poly1305** (AEAD).
*   **Keys:** Derived directly from the Layer 0 (OAEP) handshake session. Relays cannot peek inside.

### 2. Erasure Coding (Sharding)
To prevent "Single Point of Failure" and censorship, OATP does not send one file to one server.
*   **Algorithm:** **Reed-Solomon** $(N, K)$.
*   **Mechanism:** Messages are split into $N$ fragments (shards). Any subset of $K$ shards is sufficient to reconstruct the message.
*   **Standard Profile:** $N=5, K=3$. This tolerates the loss or malicious behavior of up to 2 relays (40% failure rate).

### 3. Blind Relays & Inboxes
There are no "Home Servers".
*   **Relays** are dumb storage nodes. They store encrypted shards.
*   **Blind Inboxes** are used for addressing. An inbox ID is a rotating hash derived from the shared secret. It cannot be linked to the Agent's public DID by an outsider.

## 🏗 Relation to Other Layers

Layer 1 is the bridge between the mathematical trust of Layer 0 and the business logic of Layer 2.

```mermaid
graph TD
    L2[Layer 2: Application<br>(Commerce, Social, Voting)] -->|JSON-LD Payload| L1
    
    subgraph Layer 1: Transport
    L1[Encryption & Padding] -->|JWE Container| S[Sharding (Reed-Solomon)]
    S -->|Shard 1| R1[Relay A]
    S -->|Shard 2| R2[Relay B]
    S -->|Shard 3| R3[Relay C]
    end
    
    L0[Layer 0: Trust<br>(Session Keys)] -.->|Key Material| L1
```

*   **Layer 0:** Provides the keys (`sk_a_to_b`).
*   **Layer 1 (This Repo):** Uses keys to encrypt, splits data into shards, and routes them to `blind_inbox_id`.
*   **Layer 2:** Consumes the reconstructed payload (e.g., an Order Request).

## 🛠 Implementation

The OAP Foundation provides a reference implementation of the Layer 1 logic in Rust. This library handles the complex mathematics of Reed-Solomon coding and the correct padding of JWE containers.

*   **Reference Core:** [`oap-foundation/oap-core-rs`](https://github.com/oap-foundation/oap-core-rs)

**⚠️ Implementation Warning:** Implementing Reed-Solomon from scratch is prone to compatibility errors (e.g., using the wrong Galois Field generator polynomial). Use the reference core or strictly validate against the provided **Test Vectors**.

## 🤝 Contributing

We are currently in **Code Freeze** for v1.0.
We welcome feedback regarding:
*   Vectors for Erasure Coding compatibility.
*   Edge cases in the Relay API (Rate limiting, DoS protection).
*   Privacy leaks in the push notification strategy.

Please see `CONTRIBUTING.md` for details.

## 📄 License

*   **Specifications:** [Creative Commons Attribution 4.0 International](LICENSE)
*   **Code Samples:** MIT License

---
**Maintained by the OAP Foundation**
# Open Agent Transport Protocol (OATP)

[![Spec Version](https://img.shields.io/badge/spec-v1.0--RC-blue)](./RFC%20OATP%20v1.0-RC.md)
[![Layer](https://img.shields.io/badge/OAP-Layer%201-orange)](https://oap.foundation)
[![Status](https://img.shields.io/badge/status-CODE%20FREEZE-snowflake)](./RFC%20OATP%20v1.0-RC.md)
[![License](https://img.shields.io/badge/license-MIT%2Fwm-green)](LICENSE)

> **⚠️ STATUS ALERT: CODE FREEZE**
>
> This specification is currently a **Release Candidate (v1.0-RC)**.
> We are in **Code Freeze**. No new features will be added. Feedback is currently limited to security audits, erasure coding vectors, and relay interoperability.

## 📦 Introduction

The **Open Agent Transport Protocol (OATP)** is "Layer 1" of the Open Agent Protocol framework. While OAEP (Layer 0) handles *Identity & Trust*, OATP handles the **Logistics & Transport** of data.

OATP is designed for a world where connectivity is intermittent, devices are mobile, and privacy is paramount. It replaces the centralized "Home Server" model (used by Matrix or Email) with a decentralized, fault-tolerant mesh of **Blind Relays**.

### Core Value Proposition
*   **Asynchronous:** Designed for "Store-and-Forward." Agents do not need to be online simultaneously.
*   **Resilient:** Messages are fragmented using **Erasure Coding (Reed-Solomon)**. Even if parts of the network fail or are censored, the message arrives.
*   **Privacy-First:** The infrastructure is "blind." Relays handle encrypted shards without knowing the sender, the content, or the true identity of the receiver.
*   **Metadata Minimization:** Uses deterministically derived "Blind Inboxes" to decouple network addresses from digital identities (DIDs).

## 🏗 Architecture

OATP operates as a containerization and delivery layer.

```text
[ Application Layer (OACP/SFP) ]  <-- JSON-LD Payload
             |
[   OATP Transport Layer (L1)  ]  <-- Encryption & Sharding
             |
[      Blind Relay Mesh        ]  <-- Dumb Storage Nodes
```

### The Delivery Flow
1.  **Encrypt:** Payload is wrapped in a **JWE Container** using OAEP session keys.
2.  **Shard:** The container is split into $N$ fragments (shards) using Reed-Solomon codes.
3.  **Scatter:** Shards are uploaded to different, independent Relays.
4.  **Reassemble:** The receiver polls relays, downloads $K$ shards, and mathematically reconstructs the original message.

## 📂 The Specification

The full normative specification is available here:

👉 **[READ THE SPECIFICATION (v1.0-RC)](RFC%20OATP%20v1.0-RC.md)**

### Quick Navigation
*   [Section 3: The Message Container (JWE)](RFC%20OATP%20v1.0-RC.md#section-3-the-message-container)
*   [Section 4: Sharding & Erasure Coding](RFC%20OATP%20v1.0-RC.md#section-4-sharding--erasure-coding)
*   [Section 5: The Relay Protocol (API)](RFC%20OATP%20v1.0-RC.md#section-5-the-relay-protocol)
*   [Section 6: Reliability & Retries](RFC%20OATP%20v1.0-RC.md#section-6-delivery-reliability)
*   [Section 8: Implementation Guidelines](RFC%20OATP%20v1.0-RC.md#section-8-implementation-guidelines)

## ⚡ Technical Standards

Implementers must strictly adhere to these primitives to ensure interoperability across the network:

| Component | Specification / Algorithm |
| :--- | :--- |
| **Container Format** | **JWE** (Compact Serialization) |
| **Encryption** | **ChaCha20-Poly1305** (AEAD) |
| **Erasure Coding** | **Reed-Solomon** over $GF(2^8)$ with Poly `0x11D` |
| **Addressing** | Blind Inboxes (Ed25519 Derived Hash) |
| **Transport** | HTTPS (REST) with TLS 1.3 |
| **Push Strat** | UnifiedPush (Android) / APNS (iOS) |

### Default Sharding Profile
*   **N (Total Shards):** 5
*   **K (Threshold):** 3
*   *Resilience:* Can tolerate the loss of 2 relays (40% failure rate).

## 🛠 Relay API Example

Relays are simple HTTP servers. They do not hold user accounts.

**Upload a Shard (Sender):**
```http
POST /v1/inbox/{blind_inbox_id}
X-OATP-TTL: 604800
Content-Type: application/json

{
  "shard_id": "uuid...",
  "data": "encrypted_blob..."
}
```

**Retrieve Shards (Receiver):**
```http
GET /v1/inbox/{blind_inbox_id}
Authorization: Bearer <Signature_over_Timestamp>
```

## 🧪 Implementation & Testing

The OAP Foundation provides the reference implementation in Rust. This core logic handles the complex mathematics of Reed-Solomon and AEAD.

*   **Reference Core:** [`oap-foundation/oap-core-rs`](https://github.com/oap-foundation/oap-core-rs)
*   **Test Vectors:** See [Appendix 9.3](RFC%20OATP%20v1.0-RC.md#93-kryptografische-test-vektoren) for Hex vectors to validate your RS-Coder.

**Warning for Developers:**
> Do not use generic Reed-Solomon libraries without verifying the polynomial (`0x11D`) and the field generator. Incompatibility here will result in undecodable messages.

## 🤝 Contributing

We are currently in **Code Freeze**.
*   **Accepted:** Bug reports regarding the Sharding logic, Relay API inconsistencies, or Security vulnerabilities.
*   **Not Accepted:** Feature requests for new transport layers (e.g., QUIC) or different coding schemes (e.g., RaptorQ) are deferred to v1.1.

Please review `CONTRIBUTING.md` before submitting PRs.

## 📄 License

Specification text: **CC BY 4.0 International**.
Code samples and schemas: **MIT**.

---
**Maintained by the OAP Foundation**
*Building the logistics layer of the agent economy.*
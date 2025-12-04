# RFC: Open Agent Transport Protocol (OATP)
**Version:** 1.0 (PROPOSED STANDARD)
**Status:** CODE FREEZE
**Date:** 2025-11-25

**Section 1: Introduction**

## 1. Einleitung

Das *Open Agent Exchange Protocol (OAEP)* hat die Grundlage für dezentrale Identität und vertrauenswürdige Sitzungsschlüssel gelegt (Layer 0). Doch Identität allein ermöglicht noch keine Kommunikation. In einer Welt mobiler Endgeräte, instabiler Netzwerkverbindungen und zunehmender Internetzensur reicht es nicht aus, sich auf die traditionelle Client-Server-Architektur des Web 2.0 zu verlassen.

Das **Open Agent Transport Protocol (OATP)** ist der **Transport-Layer (Schicht 1)** des OAP-Frameworks. Es definiert den Standard für den asynchronen, verschlüsselten und fragmentierten Austausch von Datenpaketen zwischen Agenten. OATP entkoppelt die Nachrichtenzustellung von der physischen Netzwerktopologie und ersetzt zentrale Datensilos durch ein Netzwerk aus "blinden" Vermittlern (Blind Relays).

### 1.1 Purpose (Zweck)

Der Zweck von OATP ist die Bereitstellung eines universellen **Logistik-Netzwerks** für digitale Nachrichten. Es fungiert als "Container-Schiff" für alle höherwertigen Anwendungsprotokolle (wie OACP für Handel oder SFP für Social Media).

OATP garantiert:
1.  **Vertraulichkeit:** Der Inhalt ist Ende-zu-Ende-verschlüsselt (basierend auf OAEP-Keys).
2.  **Integrität:** Änderungen am Nachrichteninhalt werden kryptografisch erkannt.
3.  **Verfügbarkeit:** Nachrichten erreichen den Empfänger auch dann, wenn dieser zum Zeitpunkt des Absendens offline ist ("Store-and-Forward").
4.  **Transport-Agnostik:** OATP definiert das Paketformat und die Routing-Logik, ist aber unabhängig vom darunterliegenden Transportkanal (TCP, UDP, WebSocket, Bluetooth LE oder Sneaker-Net).

### 1.2 The Problem (Die Problemstellung)

Die heutige digitale Kommunikation leidet unter systemischen Defiziten, die OATP adressiert:

*   **Metadaten-Überwachung (Metadata Leakage):**
    Zentralisierte Messenger (wie WhatsApp oder Telegram) verschlüsseln zwar oft den Inhalt, speichern aber die Metadaten: *Wer* kommuniziert mit *wem*, *wann* und *wie oft*? Diese Verkehrsdaten (Traffic Patterns) sind oft aussagekräftiger als der Inhalt selbst. OATP minimiert diese Spuren durch Architektur-Design.

*   **Single Points of Failure & Control:**
    Fällt der zentrale Server aus oder entscheidet der Betreiber, einen Nutzer zu sperren, kommt die Kommunikation zum Erliegen. In der Web2-Welt diktiert die Infrastruktur die Kommunikationsfähigkeit.

*   **Das "Offline-Problem" in P2P-Netzen:**
    Reine Peer-to-Peer-Netzwerke scheitern oft an der Realität mobiler Geräte. Smartphones wechseln Netzwerke, gehen in den Energiesparmodus oder verlieren das Signal. Eine direkte synchrone Verbindung ist selten dauerhaft möglich. Es wird eine Zwischenspeicherung benötigt, die jedoch traditionell Vertrauen in den Speicheranbieter erfordert.

### 1.3 Core Philosophy (Kernphilosophie)

OATP löst diese Probleme durch drei radikale Design-Prinzipien:

1.  **Blind Delivery (Blinde Zustellung):**
    Die Infrastruktur (die Relay-Server) darf **nichts** wissen. Ein Relay weiß nicht, wer der Absender ist, und kann den Inhalt nicht lesen. Es weiß lediglich, dass ein verschlüsseltes Datenpaket in eine bestimmte "Mailbox" (identifiziert durch einen pseudonymen Hash) gelegt werden soll. Das Netzwerk ist "smart enough to deliver, but too dumb to spy".

2.  **Resilience via Sharding (Ausfallsicherheit durch Fragmentierung):**
    OATP verlässt sich nicht auf einen einzelnen Server. Nachrichten werden mittels *Erasure Coding* (Reed-Solomon) in mehrere Fragmente (**Shards**) zerlegt und über verschiedene, unabhängige Relays verteilt.
    *   *Effekt:* Fällt ein Relay aus oder wird zensiert, kann der Empfänger die Nachricht aus den verbleibenden Fragmenten vollständig rekonstruieren. Es gibt keinen "Single Point of Failure" mehr.

3.  **Asynchronicity First (Asynchronität):**
    Das Protokoll geht davon aus, dass Sender und Empfänger **nicht** gleichzeitig online sind. Es ist als "Dead Drop"-System konzipiert. Agenten werfen Nachrichten in Relays ein und holen sie ab, wenn sie Konnektivität haben. Synchrone Echtzeit-Kommunikation ist ein Spezialfall, nicht der Standard.
    
---

**Section 2: Terminology & Architecture**

## 2. Terminologie und Architektur

OATP bricht mit dem klassischen Client-Server-Modell, bei dem ein Server als vertrauenswürdige Instanz (Trusted Third Party) agiert. Stattdessen definiert es eine Architektur, in der die Infrastruktur als **unvertrauenswürdig (untrusted)** betrachtet wird. Um Missverständnisse zu vermeiden, werden die Rollen und Komponenten in diesem Abschnitt normativ definiert.

Die Schlüsselwörter "MUSS", "DARF NICHT", "SOLLTE" und "KANN" sind entsprechend RFC 2119 zu interpretieren.

### 2.1 Akteure und Komponenten (Actors)

*   **Agent (Sender / Receiver):**
    Ein Software-Endpunkt (Identifiziert durch eine DID), der OATP-Nachrichten erstellt oder empfängt. Agenten sind die einzigen Entitäten im System, die Zugriff auf die privaten Schlüssel (aus OAEP) haben und somit die einzigen, die den Inhalt einer Nachricht im Klartext sehen können.
    *   *Sender:* Der Ersteller der Nachricht. Er ist verantwortlich für Verschlüsselung, Fragmentierung (Sharding) und Versand.
    *   *Receiver:* Der Empfänger. Er ist verantwortlich für das Abholen (Polling/Push), die Rekonstruktion und Entschlüsselung.

*   **Relay (Blind Relay):**
    Ein Server-Knoten im Netzwerk, der OATP-Pakete empfängt, temporär speichert und auf Anfrage ausliefert.
    *   **Blindheit:** Ein Relay MUSS als "blind" konzipiert sein. Es kennt weder den Inhalt (da verschlüsselt) noch zwangsläufig die Identität des Absenders. Es agiert als "Dead Drop" (toter Briefkasten).
    *   **Untrusted:** Das Protokoll geht davon aus, dass Relays kompromittiert sein können (Honest-but-Curious oder böswillig). Die Sicherheit der Nachricht darf nicht von der Integrität des Relays abhängen.

*   **Message Container (Umschlag):**
    Die vollständige, verschlüsselte Dateneinheit, bevor sie fragmentiert wird. Sie enthält den Payload (z.B. eine OACP-Bestellung) sowie Metadaten für den Empfänger (z.B. Zeitstempel, Signatur).

*   **Shard (Fragment):**
    Ein Teilsegment eines Message Containers, das durch *Erasure Coding* (siehe Kapitel 4) erzeugt wurde. Ein einzelner Shard ist nutzlos und enthält keine lesbaren Informationen. Erst die Kombination einer definierten Anzahl von Shards ($K$) ermöglicht die Wiederherstellung des Containers.

*   **Inbox (Postfach):**
    Eine logische Adressierung auf einem Relay. Um Metadaten zu schützen, ist die Inbox-ID NICHT identisch mit der DID des Empfängers. Sie ist ein abgeleiteter, rotierender Hash-Wert (Blind Identifier), der nur dem Sender und Empfänger bekannt ist.

### 2.2 Das OAP Schichtenmodell (Layer Model)

OATP operiert als mittlere Schicht im OAP-Stack. Es nutzt die darunterliegende Vertrauensschicht und transportiert die darüberliegende Anwendungsschicht.

```text
+-------------------------------------------------------+
|  Layer 2: Application Layer (Payload)                 |
|  (OACP, SFP, OAPP, OACoP)                             |
|  -> Definiert WAS kommuniziert wird (JSON-LD)         |
+-------------------------------------------------------+
|                                                       |
|            V E R S C H L Ü S S E L U N G              |
|                                                       |
+-------------------------------------------------------+
|  Layer 1: Transport Layer (OATP) - DIESES RFC         |
|  -> Definiert WIE es transportiert wird               |
|  -> Container-Format, Sharding, Routing, Relays       |
+-------------------------------------------------------+
|                                                       |
|            A U T H E N T I F I Z I E R U N G          |
|                                                       |
+-------------------------------------------------------+
|  Layer 0: Trust Layer (OAEP)                          |
|  -> Definiert WER kommuniziert (DIDs, Keys)           |
|  -> Handshake, Session Keys, Signaturen               |
+-------------------------------------------------------+
```

1.  **Input:** OATP erhält von Layer 2 ein JSON-LD Objekt (z.B. `OrderRequest`) und von Layer 0 die symmetrischen Session-Keys (`sk_a_to_b`).
2.  **Processing:** OATP verpackt das Objekt, verschlüsselt es (AEAD), zerteilt es in Shards und verteilt diese an Relays.
3.  **Output:** Physische HTTP/TCP-Pakete an verschiedene IP-Adressen.

### 2.3 Architektur-Konzept: Distributed Resilience

Die Architektur von OATP unterscheidet sich fundamental von E-Mail (SMTP) oder Matrix. Es gibt keinen "Heimat-Server" (Home Server), auf dem alle Daten eines Nutzers liegen.

*   **Empfänger-zentriertes Routing:**
    Das DID Document des Empfängers definiert eine Liste von *möglichen* Relays (Service Endpoints). Der Sender wählt aus dieser Liste eine Teilmenge aus.
*   **Erasure Coding (Redundanz):**
    Nachrichten werden mittels eines $(N, K)$-Schemas kodiert.
    *   $N$: Gesamtanzahl der erzeugten Shards (z.B. 5).
    *   $K$: Mindestanzahl der Shards, die zur Wiederherstellung nötig sind (z.B. 3).
    *   **Resilienz:** Solange $K$ Relays erreichbar sind und die Daten liefern, kommt die Nachricht an. Der Ausfall oder die Zensur von $N-K$ Relays (im Beispiel 2) wird mathematisch kompensiert.
*   **Ephemere Speicherung:**
    Relays sind keine Datenbanken für die Ewigkeit. Sie puffern Nachrichten nur ("Store-and-Forward"), bis der Empfänger sie abholt (oder eine TTL abläuft). Langzeitspeicherung (History) ist Aufgabe der lokalen Datenbank des Agenten (Client-Side Storage).

---

**Section 3: The Message Container**

## 3. Der Nachrichten-Container (The Message Container)

Der **OATP-Container** ist die atomare Einheit der sicheren Kommunikation. Er kapselt die Nutzdaten der Anwendungsschicht (Layer 2, z.B. eine OACP-Bestellung) in eine kryptografisch geschützte Hülle.

Dieser Container wird vom Absender erzeugt, verschlüsselt und anschließend an die Sharding-Schicht (siehe Kapitel 4) übergeben. Der Empfänger rekonstruiert diesen Container aus den Shards und entschlüsselt ihn.

**Design-Entscheidung:** Um maximale Interoperabilität und Sicherheit zu gewährleisten, basiert das Container-Format auf **JWE (JSON Web Encryption, RFC 7516)** unter Verwendung der *Compact Serialization*.

### 3.1 Struktur des Containers

Da die Schlüssel bereits via OAEP ausgehandelt wurden, wird auf das Senden eines verschlüsselten Content-Encryption-Keys (Key Wrapping) verzichtet. Wir nutzen **Direct Encryption**.

#### 3.1.1 JWE Compact Serialization
Der Container besteht aus fünf Teilen, getrennt durch Punkte:
`Header.EncryptedKey.IV.Ciphertext.AuthenticationTag`

Da das Feld `EncryptedKey` bei Direct Encryption leer ist, ergibt sich folgendes Format:
`BASE64URL(Header)..BASE64URL(IV).BASE64URL(Ciphertext).BASE64URL(Tag)`

#### 3.1.2 The Protected Header
Der Header enthält Metadaten für das Routing, die Entschlüsselung und den Replay-Schutz. Er ist **integritätsgeschützt** (Teil der AEAD-Berechnung), aber für das Relay (aufgrund des Shardings) nicht lesbar.

```json
{
  "alg": "dir",                      // Algorithmus: Direct Encryption
  "enc": "C20P",                     // Encryption: ChaCha20-Poly1305 (gemäß OAEP Suite)
  "kid": "a1b2c3d4...",              // Key ID: Die Session-ID (Hash des OAEP-Transkripts)
  "seq": 42,                         // OATP-Message-Sequence (für Nonce-Ableitung & Anti-Replay)
  "zip": "DEF",                      // Optional: Kompression (DEFLATE) vor Verschlüsselung
  "typ": "OATP+JSON"                 // Media Type
}
```

**Normative Feld-Definitionen:**

*   **`alg` (Algorithm):** MUSS auf `dir` gesetzt sein. Dies signalisiert, dass der symmetrische Schlüssel direkt verwendet wird (Shared Secret aus OAEP).
*   **`enc` (Encryption Method):** MUSS der in der OAEP-Session ausgehandelten Cipher Suite entsprechen (z.B. `C20P` für ChaCha20-Poly1305 oder `A256GCM` für AES-GCM).
*   **`kid` (Key ID / Session ID):** Dieses Feld identifiziert die aktive **OAEP-Sitzung**.
    *   *Wert:* Die ersten 16 Bytes des *Handshake-Transkript-Hashs* ($H_T$) aus OAEP v1.0 (Abschnitt 5.2).
    *   *Zweck:* Erlaubt dem Empfänger, bei mehreren parallelen Sitzungen (z.B. nach einem Re-Keying) den korrekten Entschlüsselungs-Key im Speicher zu finden.
*   **`seq` (Sequence Number):** Ein 64-Bit Unsigned Integer, der vom Sender pro Session inkrementiert wird.
    *   *Zweck:* Dient der Erkennung von Nachrichtenverlusten, der Sortierung und dem Replay-Schutz.
    *   *Wichtig:* Diese Sequenznummer ist logisch an die OATP-Nachricht gebunden und dient als **Input für die HKDF-basierte Nonce-Ableitung** (siehe 3.3.3). Sie stellt sicher, dass jede Nachricht eine einzigartige Nonce erhält, auch wenn sie "out-of-order" eintrifft.
*   **`typ` (Type):** MUSS auf `OATP+JSON` gesetzt sein.

#### 3.1.3 Initialization Vector (IV / Nonce)
Im JWE-String wird der IV (die Nonce) base64-kodiert übertragen.
*   **Konstruktion:** Der Sender MUSS die Nonce deterministisch aus der Sequenznummer (`seq`) und dem Sitzungsschlüssel ableiten, wie in Abschnitt 3.3.3 definiert.
*   **Validierung:** Der Empfänger MUSS prüfen, ob die im JWE-String übertragene Nonce mit der im Header enthaltenen `seq` übereinstimmt (indem er die Ableitung lokal wiederholt). Ist dies nicht der Fall, MUSS das Paket verworfen werden.

### 3.2 Die Nutzlast (The Payload)

Bevor die Daten verschlüsselt werden, muss der Plaintext (Klartext) strukturiert werden. Der Plaintext besteht aus zwei Teilen: Dem eigentlichen JSON-LD-Objekt und dem Traffic Padding.

#### 3.2.1 Plaintext-Struktur
Der Plaintext ist ein UTF-8 kodiertes JSON-Objekt:

```json
{
  "meta": {
    "created": "2026-10-12T10:00:00Z", // Zeitstempel (RFC 3339)
    "ttl": 86400,                       // Time-to-Live in Sekunden
    "type": "https://w3id.org/oacp/v1/OrderRequest" // Payload-Typ
  },
  "data": { ... },                      // Das eigentliche Layer-2 Objekt
  "padding": "..."                      // Zufällige Bytes zur Längen-Verschleierung
}
```

*   **`created`**: Dient dem Empfänger zur Prüfung, ob die Nachricht veraltet ist (Replay-Schutz-Fenster).
*   **`data`**: Enthält das eigentliche Anwendungsobjekt (z.B. OACP).

### 3.3 Verschlüsselung (Encryption Process)

Die Verschlüsselung transformiert den Plaintext (das JSON-Objekt) in den Ciphertext. OATP nutzt hierfür **AEAD** (Authenticated Encryption with Associated Data), um Vertraulichkeit und Integrität gleichzeitig zu sichern.

Der Prozess folgt diesen vier Schritten:

#### 3.3.1 Traffic Padding (Verschleierung der Länge)
Bevor verschlüsselt wird, MUSS die Länge der Nachricht verschleiert werden, um Rückschlüsse auf den Inhalt (Seitenkanalangriffe) zu verhindern.
*   **Mechanismus:** Der Sender fügt dem Plaintext-JSON im Feld `padding` kryptografisch zufällige Bytes hinzu.
*   **Zielgröße:** Die Gesamtgröße des Plaintexts SOLLTE auf das nächste Vielfache von **256 Bytes** (oder eine Zweierpotenz) aufgefüllt werden.
*   *Beispiel:* Eine Nachricht von 150 Bytes wird mit 106 Bytes Padding auf 256 Bytes gebracht.

#### 3.3.2 Schlüsselauswahl
Der Sender wählt den korrekten symmetrischen Schlüssel aus dem aktiven OAEP-Kontext.
*   Ist der Sender der **Initiator** der Session, verwendet er den `Client_Write_Key`.
*   Ist der Sender der **Responder**, verwendet er den `Server_Write_Key`.

#### 3.3.3 Nonce-Ableitung (HKDF-basiert)
Die Sicherheit von AEAD (insbesondere ChaCha20-Poly1305) hängt kritisch von der Einmaligkeit der Nonce (IV) ab. Eine Wiederverwendung führt zum Verlust der Vertraulichkeit.

Um Kollisionen mit anderen Protokollen, die denselben OAEP-Sitzungsschlüssel nutzen könnten, auszuschließen und "Out-of-Order"-Entschlüsselung zu ermöglichen, DARF die Nonce NICHT einfach ein aufgefüllter Zähler sein. Stattdessen MUSS sie deterministisch mittels **HKDF-Expand** (gemäß RFC 5869) aus der Sequenznummer (`seq`) abgeleitet werden.

**Der Algorithmus:**

1.  **Hash-Funktion:** Es MUSS dieselbe Hash-Funktion verwendet werden, die in der aktiven OAEP-Cipher-Suite definiert ist (z.B. **BLAKE3** für `OAEP-v1-2026`).
2.  **Inputs:**
    *   **PRK (Pseudo-Random Key):** Der für die Verschlüsselung gewählte Session Key (`Client_Write_Key` oder `Server_Write_Key`).
    *   **Info (Context):** Eine Konkatenation aus dem ASCII-String `"OATP-Nonce-v1"` und der 64-Bit Big-Endian Repräsentation der Sequenznummer `seq` aus dem Header.
    *   **L (Length):** 12 Bytes (96 Bit).
3.  **Operation:**
    `Nonce = HKDF-Expand(PRK, Info="OATP-Nonce-v1" || BigEndian(seq), L=12)`

**Beispiel-Konstruktion:**
Wenn `seq = 42` und der Hash BLAKE3 ist:
`Nonce = BLAKE3_KDF(Key, Context="OATP-Nonce-v1" + 0x000000000000002A)` (auf 12 Bytes gekürzt).

**Vorteil:** Durch diese Ableitung ist die Nonce statistisch unabhängig von der Sequenznummer. Dies verhindert Korrelationsangriffe und stellt sicher, dass OATP-Nachrichten sicher entschlüsselt werden können, selbst wenn sie in falscher Reihenfolge (Out-of-Order) beim Empfänger eintreffen und verarbeitet werden.

#### 3.3.4 AEAD-Operation
Die Verschlüsselung erfolgt gemäß JWE-Standard (RFC 7516).

1.  **Input:**
    *   `K` (Key): Der gewählte Session Key.
    *   `IV` (Nonce): Die abgeleitete 12-Byte Nonce.
    *   `AAD` (Associated Data): Der **Protected Header** (Base64URL-kodiert). Dies bindet die Metadaten (`seq`, `kid`) kryptografisch an den Ciphertext.
    *   `P` (Plaintext): Das gepaddete JSON-Objekt.
2.  **Operation:**
    `Ciphertext, Tag = ChaCha20_Poly1305_Encrypt(K, IV, AAD, P)`
3.  **Output:**
    Der JWE Compact String wird aus Header, IV, Ciphertext und Tag zusammengesetzt.

### 3.4 Entschlüsselung (Decryption Process)

Der Empfänger führt nach Erhalt und Rekonstruktion (Reassembly) des Containers folgende Schritte durch:

1.  **Session Lookup:** Anhand der `kid` im Header wird die korrekte OAEP-Sitzung und der zugehörige `Client_Write_Key` (bzw. `Server_Write_Key`) geladen.
2.  **Replay Check:** Die `seq` im Header wird gegen das lokale "Sliding Window" geprüft. Bereits verarbeitete Sequenznummern werden verworfen.
3.  **Nonce Reconstruction:** Aus der `seq` im Header und dem bekannten Sitzungsschlüssel wird die Nonce mittels HKDF (siehe 3.3.3) lokal neu berechnet.
4.  **AEAD Decryption:**
    *   `Plaintext = AEAD_Decrypt(Key, Nonce, Header, Ciphertext, Tag)`
    *   Schlägt die Integritätsprüfung (Tag-Check) fehl, MUSS der Container verworfen werden (`ERR_DECRYPT_FAILED`).
5.  **Zeit-Prüfung:** Ist `meta.created + meta.ttl < now`? Wenn ja -> Verwerfen (Nachricht abgelaufen).

### 3.5 Interaktion mit Sharding

Es ist wichtig zu betonen: **Das Relay sieht diesen Container niemals im Ganzen.**
Der hier definierte Container ist der Input für den *Erasure Coding*-Prozess (Kapitel 4). Das Relay sieht nur Fragmente (Shards), die statistisch wie Zufallsrauschen aussehen. Selbst wenn ein Relay den Header eines Shards lesen könnte, fehlt ihm der Rest der Daten und der Schlüssel. Der JWE-Container existiert logisch nur auf den Endgeräten (Sender/Empfänger).

---

**Section 4: Sharding & Erasure Coding**

## 4. Sharding & Erasure Coding (Fragmentierung)

Das zentrale Designziel von OATP ist Resilienz. In herkömmlichen Systemen führt der Ausfall oder die Zensur des Mail-Servers zum Verlust der Kommunikationsfähigkeit. OATP eliminiert diesen "Single Point of Failure" durch die Anwendung von **Erasure Coding** auf der Transportschicht.

Der in Kapitel 3 definierte, verschlüsselte *Message Container* wird nicht als Ganzes übertragen. Stattdessen wird er in eine Menge von $N$ Fragmenten (**Shards**) expandiert, von denen eine beliebige Teilmenge von $K$ Shards ausreicht, um die Nachricht vollständig zu rekonstruieren.

### 4.1 Der Algorithmus: Reed-Solomon

OATP schreibt die Verwendung von **Reed-Solomon (RS) Codes** vor. Damit verschiedene Implementierungen (Rust, JavaScript, Python) kompatible Shards erzeugen, werden die Parameter in diesem Abschnitt strikt normiert.

#### 4.1.1 Parameter-Wahl ($N, K$)
Der Absender bestimmt die Parameter $N$ (Gesamtanzahl der Shards) und $K$ (Benötigte Shards zur Wiederherstellung) basierend auf der gewünschten Redundanz.

Um Interoperabilität auf allen Geräteklassen zu gewährleisten und Missbrauch (Relay-Flooding) zu verhindern, gelten folgende **normative Grenzwerte**:

1.  **Maximum Shards ($N_{max}$):** Die Gesamtanzahl $N$ DARF den Wert **16** NICHT überschreiten.
    *   *Begründung:* Dies begrenzt den Overhead für Relays und hält die Komplexität der Reed-Solomon-Dekodierung auf leistungsschwachen IoT-Geräten gering.
2.  **Minimum Threshold ($K_{min}$):** Der Wert $K$ MUSS mindestens **1** betragen.
3.  **Redundanz-Bedingung:** Es MUSS gelten: $1 \le K < N \le 16$.

**Empfohlenes Standard-Profil:**
Für gewöhnliche Nachrichten SOLLTE das Schema **$(N=5, K=3)$** verwendet werden.
*   *Effizienz:* Dies entspricht einem Overhead von 66%.
*   *Resilienz:* Bis zu 2 Relays können ausfallen, zensiert oder korrumpiert werden, ohne den Nachrichtenfluss zu stören (Failure Tolerance = 40%).

#### 4.1.2 Kodierungs-Prozess
1.  Der verschlüsselte *Message Container* (siehe Kap. 3) wird als Input-Blob betrachtet.
2.  Der Blob wird in $K$ gleich große Datenblöcke unterteilt (Padding mit Nullen, falls nötig, siehe 4.1.3).
3.  Der RS-Encoder generiert daraus $N$ Output-Blöcke (Shards).
4.  Jeder dieser Blöcke bildet die Nutzlast (Payload) eines *OATP Shard Pakets*.

#### 4.1.3 Normative Algorithmus-Spezifikation (Reed-Solomon)
Um Bit-genaue Kompatibilität zwischen verschiedenen Implementierungen zu garantieren, schreibt OATP v1.0 exakte Parameter für die Erasure-Coding-Mathematik vor. Alle Implementierungen **MÜSSEN** den folgenden Standard einhalten:

1.  **Galois-Feld:** Die Operationen finden im endlichen Körper **$GF(2^8)$** statt. Dies ermöglicht die direkte Verarbeitung von Bytes (Symbole von 0 bis 255).
2.  **Generator-Polynom:** Es MUSS das irreduzible Polynom **$p(x) = x^8 + x^4 + x^3 + x^2 + 1$** verwendet werden.
    *   In Hexadezimal-Notation entspricht dies **`0x11D`** (bzw. dezimal 285).
    *   *Hinweis:* Dies ist der De-facto-Standard (u.a. verwendet in QR-Codes und CCSDS), unterscheidet sich jedoch vom AES-Polynom (`0x11B`). Implementierer müssen sicherstellen, dass ihre Bibliothek `0x11D` nutzt.
3.  **Systematische Kodierung:** Der Encoder MUSS **systematisch** arbeiten.
    *   Das bedeutet: Die ersten $K$ erzeugten Shards (Index $0$ bis $K-1$) sind exakte Kopien der Input-Datenblöcke.
    *   Die verbleibenden Shards (Index $K$ bis $N-1$) enthalten die berechneten Paritätsdaten.
4.  **Padding:** Ist die Länge des verschlüsselten *Message Containers* (in Bytes) nicht ohne Rest durch $K$ teilbar, MUSS der Input am Ende mit **Null-Bytes (`0x00`)** aufgefüllt werden, bis die Länge ein Vielfaches von $K$ ist. Dieses Padding wird beim Entschlüsseln automatisch ignoriert/entfernt.

### 4.2 Das Shard-Paketformat

Damit der Empfänger die Fragmente korrekt zusammensetzen kann, benötigt jedes Fragment Metadaten (Index, Gesamtanzahl, Message-ID).

**Sicherheits-Vorschrift:** Diese Metadaten MÜSSEN verschlüsselt sein. Das Relay darf keine Korrelation zwischen Fragmenten herstellen können.

#### 4.2.1 The Relay Envelope (Der Umschlag)
Das an das Relay gesendete JSON-Objekt (via `POST /inbox`) enthält ausschließlich Informationen, die für das Routing und das Speichermanagement notwendig sind.

```json
{
  "inbox": "hmac_derived_hash_xyz",  // Die Ziel-Adresse (Blind Inbox)
  "shard_id": "uuid-v4-random",      // Einzigartige ID für DELETE-Operationen
  "ttl": 604800,                     // Gewünschte Lebensdauer (Sekunden)
  "data": "BASE64_ENCRYPTED_BLOB..." // Verschlüsseltes Shard-Bundle
}
```

*   **`shard_id`**: Eine zufällige UUIDv4. Sie darf **nicht** aus Inhaltsdaten abgeleitet sein, um Deduplizierungs-Leaks zu vermeiden.
*   **`data`**: Der Ciphertext, der die eigentlichen Informationen enthält.

#### 4.2.2 The Shard Bundle (Der Inhalt)
Das Feld `data` im Envelope ist das Ergebnis einer AEAD-Verschlüsselung des **Shard Bundles**. Dieses innere Objekt ist nur für den Empfänger sichtbar.

```json
{
  "msg_id": "hash(container_iv)",   // ID der Gesamtnachricht (zur Gruppierung)
  "idx": 0,                         // Index dieses Shards (0 bis N-1)
  "total": 5,                       // Gesamtanzahl N
  "threshold": 3,                   // Benötigte Anzahl K
  "payload": "BASE64_RS_CHUNK..."   // Das rohe Reed-Solomon-Fragment
}
```

#### 4.2.3 Verschlüsselung der Metadaten (Shard Encryption)
Um das *Shard Bundle* in das `data`-Feld des Envelopes zu verwandeln, verwendet der Sender denselben symmetrischen Schlüssel wie für die Nachricht selbst (aus der OAEP-Session).

1.  **Nonce-Bildung:** Um Overhead zu sparen, wird die Nonce (IV) für die Shard-Verschlüsselung deterministisch aus der `shard_id` des äußeren Umschlags abgeleitet (z.B. die ersten 12 Bytes des SHA-256 Hashs der UUID).
    *   *Vorteil:* Das Relay kann die `shard_id` nicht manipulieren, ohne die Entschlüsselung zu brechen (Integrity Binding).
2.  **Operation:**
    `data = ChaCha20_Poly1305(Key, Nonce=Hash(shard_id), Plaintext=BundleJSON)`

**Sicherheitsgewinn:**
Da jedes Shard-Paket eine eigene, zufällige `shard_id` hat, erzeugt die Verschlüsselung selbst bei identischem Inhalt (z.B. Retries) oder zusammengehörigen Fragmenten (`msg_id`) vollkommen unterschiedliche Ciphertexte. Ein Relay kann nicht unterscheiden, ob fünf Shards zu einer Nachricht oder zu fünf verschiedenen Nachrichten gehören.

### 4.3 Distribution Strategy (Verteilungsstrategie)

Die Sicherheit von OATP basiert auf der Annahme, dass ein Angreifer nicht *alle* Relays gleichzeitig kontrollieren kann. Daher ist die Auswahl der Relays kritisch.

#### 4.3.1 Relay Discovery
Der Sender konsultiert das DID Document des Empfängers. Im Abschnitt `service` finden sich Einträge vom Typ `OAPEndpoint`. Diese enthalten Listen von Relay-URLs.

#### 4.3.2 Diversity Routing (Diversitäts-Routing)
Der Sender MUSS die $N$ Shards so verteilen, dass die Wahrscheinlichkeit eines *Common Mode Failure* minimiert wird.

1.  **Unique Relays:** Soweit möglich, SOLLTE jeder Shard an ein anderes Relay gesendet werden.
2.  **Topologische Distanz:** Wenn der Empfänger Relays in verschiedenen Jurisdiktionen oder bei verschiedenen Providern (AWS, Hetzner, Home-Server) angibt, SOLLTE der Sender die Shards über diese Gruppen streuen.
3.  **Mindestverteilung:** Die $N$ Shards MÜSSEN an mindestens $K$ physikalisch getrennte Relays gesendet werden (sofern verfügbar). Das Senden aller Shards an dasselbe Relay ist VERBOTEN (außer in reinen Testumgebungen), da dies die Resilienz negiert.

### 4.4 Reassembly & Integrity (Rekonstruktion)

Der Prozess auf der Empfängerseite:

1.  **Polling/Push:** Der Empfänger prüft seine (ihm bekannten) Blind Inboxes auf den relevanten Relays.
2.  **Sammlung:** Er lädt alle verfügbaren Shards herunter.
3.  **Gruppierung:** Shards werden anhand der `msg_id` gruppiert.
4.  **Prüfung:** Sobald $\ge K$ Shards für eine `msg_id` vorhanden sind, beginnt die Rekonstruktion.
5.  **RS-Decode:** Der Reed-Solomon-Algorithmus rekonstruiert den ursprünglichen *Message Container*.
6.  **Integritäts-Check:**
    *   Der Empfänger führt die AEAD-Entschlüsselung (ChaCha20-Poly1305) auf dem rekonstruierten Container durch.
    *   **Kritisch:** Wenn der **Authentication Tag** des Containers invalide ist, bedeutet dies, dass mindestens einer der verwendeten Shards manipuliert (korrumpiert) wurde.
7.  **Fehlerbehandlung:**
    *   Bei Integritätsfehler: Wenn der Empfänger mehr als $K$ Shards hat (z.B. er hat 4 von 5), kann er durch permutatives Probieren (Brute Force der Kombinationen) versuchen, die korrupten Shards zu identifizieren und auszuschließen.
    *   Gelingt die Rekonstruktion nicht, sendet der Empfänger (sofern möglich) ein negatives Acknowledge (NACK) via OATP oder wartet auf Timeout.

---

**Section 5: Relay Protocol**

## 5. Das Relay-Protokoll (Server-Schnittstelle)

Ein OATP-Relay ist ein passiver Infrastruktur-Knoten. Seine einzige Aufgabe besteht darin, Datenblobs (Shards) anzunehmen, kurzzeitig zu speichern und an berechtigte Abholer auszuliefern.

Das Relay-Protokoll ist als **RESTful API** über **HTTPS** spezifiziert. Die Verwendung von TLS 1.3 ist ZWINGEND ("MUST"), um die Transportsicherheit zu gewährleisten.

### 5.1 Adressierung: Die Blind Inbox

Bevor die API genutzt werden kann, muss das Adressierungsschema geklärt sein. Ein OATP-Relay verwaltet keine Benutzerkonten (Accounts) im herkömmlichen Sinne. Es verwaltet temporäre, pseudonyme Speicherorte: die **Blind Inboxes**.

Um Metadaten zu schützen, DARF die Inbox-ID keine Rückschlüsse auf die DID des Empfängers zulassen.

#### 5.1.1 Deterministische Ableitung (Derivation)
Sender und Empfänger müssen sich auf eine Inbox-ID einigen. Um Overhead zu vermeiden, wird diese **deterministisch aus dem OAEP-Sitzungsgeheimnis** abgeleitet.

*   **Basis:** Das *Shared Secret* ($S_{oaep}$) aus der aktiven OAEP-Sitzung (siehe OAEP v1.0 Kap. 5.5).
*   **Kontext:** Die URL des Relays (Canonical Origin gemäß RFC 6454), um zu verhindern, dass dieselbe Inbox-ID auf mehreren Relays verwendet wird (Cross-Relay-Tracking).

**Der Algorithmus:**
Da die Inbox auch zur Authentifizierung beim Löschen dient (siehe 5.3), ist die ID technisch ein **Ed25519 Public Key**.

1.  **Inbox Seed Ableitung:**
    `Seed = HKDF(Salt=S_oaep, Info="OATP-Inbox-Derivation-" || Relay_URL, Length=32)`
2.  **Schlüssel-Generierung:**
    Aus dem `Seed` wird ein ephemeres Ed25519-Schlüsselpaar erzeugt:
    `Inbox_PrivKey, Inbox_PubKey = Ed25519_KeyGen(Seed)`
3.  **ID-Format:**
    `inbox_id = HexEncode(Inbox_PubKey)` (32 Bytes / 64 Hex-Zeichen).

#### 5.1.2 Synchronisation
*   **Der Sender:** Berechnet die `inbox_id` lokal, bevor er einen Shard sendet. Er benötigt keine Netzwerk-Interaktion mit dem Empfänger.
*   **Der Empfänger:** Berechnet ebenfalls die `inbox_id` für seine bekannten Relays und pollt diese.
*   **Rotation:** Da die Inbox an das OAEP-Shared-Secret gebunden ist, rotiert die Inbox-ID automatisch, sobald die OAEP-Sitzung erneuert wird (Re-Keying). Dies bietet *Forward Secrecy* für Adressen.

#### 5.1.3 Explicit Override (Optional)
In Sonderfällen (z.B. Einweg-Kommunikation oder Public Drops) KANN der Empfänger dem Sender eine explizite, zufällige `inbox_id` innerhalb des verschlüsselten OAEP-Kanals mitteilen ("Reply-To"-Adresse). In diesem Fall überschreibt die explizite ID die deterministische Ableitung.

#### 5.1.4 Inbox Rotation (Wahrung der Privatsphäre)
Die Verwendung einer statischen `inbox_id` über lange Zeiträume ermöglicht es einem globalen Beobachter oder dem Relay-Betreiber, Kommunikationsmuster zu erstellen (Traffic Analysis). Um dies zu verhindern, definiert OATP Mechanismen zur regelmäßigen Rotation der Empfangsadresse.

1.  **Implizite Rotation (Standard):**
    Da die deterministische Inbox-ID vom OAEP-Sitzungsgeheimnis abgeleitet wird (siehe 5.1.1), führt jede Erneuerung der OAEP-Schlüssel (Session Rotation / Re-Keying) automatisch zu neuen Inbox-IDs auf allen Relays. Agenten SOLLTEN daher regelmäßig (z.B. wöchentlich oder nach $X$ Nachrichten) einen OAEP-Re-Handshake durchführen.
2.  **Explizite Rotation (Override):**
    Ist eine Inbox kompromittiert (z.B. durch Spam geflutet) oder wünscht der Empfänger eine sofortige Rotation ohne vollständigen Session-Reset, KANN er dem Sender eine explizite neue ID mitteilen.
    *   Dies erfolgt durch eine OATP-Nachricht mit dem Payload-Typ `https://w3id.org/oatp/v1/InboxUpdate`.
    *   Nach Empfang und Validierung MUSS der Sender seinen lokalen Routing-Cache aktualisieren und zukünftige Shards an die neue ID senden.
3.  **Grace Period (Übergangsphase):**
    Um den Verlust von Nachrichten zu verhindern, die sich zum Zeitpunkt der Rotation noch im Netzwerk befinden ("In-Flight") oder die aufgrund von Latenz verzögert eintreffen, MÜSSEN Empfänger die alte Inbox für eine Übergangszeit von **mindestens 7 Tagen** weiter überwachen (Polling), nachdem eine Rotation stattgefunden hat. Erst danach darf der private Schlüssel der alten Inbox gelöscht werden.

### 5.2 API-Endpunkte (Interface Definition)

Ein OATP-konformes Relay MUSS folgende HTTP-Endpunkte bereitstellen.

#### 5.2.1 Einwurf (Delivery)
Der Sender (oder ein anderer Relay im Mesh) liefert einen Shard ab.

*   **Request:** `POST /v1/inbox/{inbox_id}`
*   **Header:**
    *   `Content-Type: application/json`
    *   `X-OATP-TTL`: Gewünschte Lebensdauer in Sekunden (Server kann dies begrenzen).
    *   `X-OATP-PoW`: (Konditional) Ein Hashcash-Token, falls das Relay dies unter Last oder generell fordert (Format siehe Abschnitt 5.6.2).
*   **Body:** Der serialisierte Shard-Envelope als JSON-Objekt (siehe Kap. 4.2.1).
*   **Response:**
    *   `201 Created`: Shard erfolgreich gespeichert.
    *   `402 Payment Required`: (Optional) Das Relay ist kostenpflichtig (siehe OAPP Integration).
    *   `413 Payload Too Large`: Shard überschreitet das normative Limit von **128 KB** (siehe 5.6.3).
    *   `429 Too Many Requests`: Das Rate-Limit für diese IP oder Inbox wurde überschritten (Token Bucket leer, siehe 5.6.1).

#### 5.2.2 Abholung (Retrieval)
Der Empfänger prüft auf neue Nachrichten.

*   **Request:** `GET /v1/inbox/{inbox_id}`
*   **Parameter:**
    *   `?since={cursor}`: (Optional) Nur Nachrichten nach einem bestimmten Zeitstempel/ID abrufen.
*   **Auth:** Erfordert Authentifizierung (siehe 5.3).
*   **Response:**
    *   `200 OK`: JSON-Liste der verfügbaren Shards (Metadaten + Payload).
    *   `204 No Content`: Inbox ist leer.

#### 5.2.3 Löschung (Acknowledgement)
Nach erfolgreicher Rekonstruktion löscht der Empfänger die Shards, um Speicherplatz freizugeben ("Good Citizen Policy").

*   **Request:** `DELETE /v1/inbox/{inbox_id}`
*   **Parameter:**
    *   `?shard_id={uuid}`: Löscht spezifischen Shard.
*   **Auth:** Erfordert Authentifizierung (siehe 5.3).
*   **Response:** `200 OK`.

### 5.3 Authentifizierung am Relay

Da Relays "blind" sind, kennen sie die OAEP-Identität (DID) des Empfängers nicht. Wie stellt das Relay sicher, dass nur der berechtigte Empfänger die Inbox leeren darf?

OATP nutzt das Konzept der **Capability-Based Authorization** oder kryptografischen Inhaberschaft.

**Mechanismus: Inbox-as-Key**
1.  Die `inbox_id` ist technisch ein öffentlicher Schlüssel (Ed25519 Public Key) oder ein Hash davon.
2.  Der Empfänger besitzt den zugehörigen privaten Schlüssel (den er *nicht* mit dem Sender teilt; der Sender kennt nur die Public ID).
3.  **Signierte Requests:** Bei `GET` oder `DELETE` Anfragen muss der Empfänger den Request (HTTP-Methode + Pfad + Timestamp) mit dem privaten Schlüssel der Inbox signieren.
4.  **Validierung:** Das Relay prüft die Signatur gegen die `inbox_id`. Ist sie gültig, wird der Zugriff gewährt.

*Vorteil:* Das Relay muss keine Benutzerdatenbank pflegen. Die Berechtigung ist mathematisch in der Adresse selbst kodiert.

### 5.4 Blind Storage Rules (Speicher-Richtlinien)

Relays sind als **"Untrusted Storage"** konzipiert. Um die Privatsphäre zu schützen und die Haftung des Betreibers zu minimieren, gelten folgende Regeln:

1.  **Opake Daten:** Das Relay DARF NICHT versuchen, den Payload zu parsen oder zu analysieren. Es behandelt den Body strikt als Byte-Stream.
2.  **Keine Indizierung:** Das Relay DARF KEINE Indizes über Metadaten (wie Dateigröße oder Timing) erstellen, die über das für den Betrieb notwendige Maß hinausgehen.
3.  **Ephemere Natur (TTL):**
    *   Jeder Shard hat eine maximale Lebensdauer (Time-To-Live).
    *   Standard-Retention: **14 Tage**.
    *   Nach Ablauf der TTL MUSS das Relay die Daten unwiderruflich löschen (Garbage Collection). OATP ist kein Archiv.
4.  **Größenbeschränkung:** Um Missbrauch als File-Sharing-Plattform zu verhindern, SOLLTEN Relays eine harte Obergrenze für die Größe einzelner Shards durchsetzen (normativ 128 KB, siehe 5.6.3). Größere Dateien müssen auf Anwendungsebene in mehrere Shard-Sets zerlegt werden.

### 5.5 Push Notifications (Wake-Up Mechanism)

Moderne mobile Betriebssysteme (iOS, Android) beenden Hintergrundverbindungen aggressiv, um Energie zu sparen. Ein dauerhaftes Polling (`GET`) ist nicht zuverlässig möglich. OATP definiert daher Mechanismen, um Geräte "aufzuwecken", wenn neue Shards verfügbar sind.

#### 5.5.1 Das Datenschutz-Dilemma
Zentralisierte Push-Dienste (Apple APNS, Google FCM) stellen ein Datenschutzrisiko dar. Selbst wenn der Inhalt leer ist, erfahren die Betreiber durch Metadaten (Zeitpunkt des Pings), *dass* ein Nutzer eine Nachricht erhält. Durch Korrelation mit dem Sendezeitpunkt können Rückschlüsse auf den Kommunikationspartner gezogen werden.

#### 5.5.2 Strategie A: UnifiedPush (Souveräner Standard)
Für Android-Systeme (und insbesondere **Th!nkOS**) ist **UnifiedPush** der bevorzugte Standard.
*   **Vorschrift:** OATP-Clients auf Android-Basis MÜSSEN UnifiedPush unterstützen.
*   **Funktionsweise:** Der Nutzer wählt seinen Push-Provider selbst (z.B. einen selbstgehosteten **ntfy**-Server oder den Relay-Betreiber selbst). Google wird vollständig aus der Signalkette entfernt.
*   **Vorteil:** Das Relay sendet das Aufweck-Signal direkt an den Server der Wahl des Nutzers. Metadaten bleiben im vertrauenswürdigen Kreis.

#### 5.5.3 Strategie B: Anonymisierte OS-Pushs (APNS/FCM)
Für iOS und Standard-Android ist die Nutzung der OS-Dienste unvermeidbar. OATP minimiert die Leaks durch **"Content-Agnostic Pings"** und **Jitter**.

1.  **Der "Empty Ping":**
    *   Das Relay sendet eine Push-Nachricht, die **keine nutzerspezifischen Daten** im Klartext enthält.
    *   Der Payload enthält lediglich den Befehl `OP: SYNC`. Er enthält **keine** Absender-ID, **keine** Vorschau und **keine** spezifische Inbox-ID (um zu verhindern, dass Apple/Google Inboxes mappen können).
2.  **Lokale Verarbeitung:**
    *   Das OS weckt die App (oder Extension) im Hintergrund.
    *   Die App verbindet sich mit *allen* ihren registrierten Relays und pollt nach neuen Shards.
    *   Erst nach erfolgreichem Download und lokaler Entschlüsselung generiert die App die sichtbare Benachrichtigung für den Nutzer.
3.  **Traffic Jitter (Verzögerung):**
    *   Um Timing-Analysen zu erschweren, SOLLTEN Relays eine konfigurierbare, zufällige Verzögerung (**Jitter**) zwischen dem Empfang eines Shards und dem Aussenden des Pushes implementieren (z.B. 0–30 Sekunden).
    *   *Hinweis:* Dies ist ein Trade-off zwischen Privatsphäre (hoher Jitter) und Usability (Echtzeit). Der Nutzer SOLLTE dies konfigurieren können.

#### 5.5.4 Trennung von Relay und Push
Aus Sicherheitsgründen SOLLTEN Relays den Push-Dienst nicht selbst betreiben, sondern an einen dedizierten **Push-Gateway** delegieren.
*   Das Relay kennt die Inbox-ID, aber nicht das Push-Token.
*   Das Push-Gateway kennt das Token, aber nicht den Inhalt oder die Inbox.
*   Dies verhindert, dass ein kompromittiertes Relay Push-Token sammelt und Nutzer deanonymisiert.

#### 5.5.5 Protokoll zwischen Relay und Push-Gateway (Normativ)
Um die Privatsphäre des Nutzers zu wahren, darf das Relay dem Push-Gateway **niemals** die `inbox_id` oder Metadaten des Shards mitteilen. Das Relay signalisiert lediglich das Vorliegen neuer Daten für ein abstraktes Handle.

**Ablauf der Registrierung (Client-seitig):**
1.  Der Client generiert lokal eine zufällige, hoch-entropische Zeichenkette: `push_ref` (mind. 128 Bit).
2.  Der Client registriert `push_ref` zusammen mit seinem OS-Push-Token beim **Push-Gateway**.
3.  Der Client registriert `push_ref` zusammen mit der URL des Gateways beim **Relay** (als Metadatum der Inbox).

**Die Benachrichtigung (Relay -> Gateway):**
Trifft ein Shard ein, führt das Relay einen `POST`-Request gegen das Gateway aus.

*   **Payload:** Das JSON-Objekt MUSS minimiert sein und darf keine Rückschlüsse auf den Inhalt zulassen.
    ```json
    {
      "ref": "random_string_generated_by_client", // Das Mapping-Handle
      "event": "SYNC",                            // Generischer Trigger
      "ts": "2026-11-23T14:30:00Z"                // Timestamp gegen Replays
    }
    ```
*   **Privacy-Vorschrift:** Das Relay **DARF NICHT** die `inbox_id`, die `shard_id`, die Größe des Shards oder die IP-Adresse des Senders an das Gateway übermitteln.
*   **Gateway-Verhalten:** Das Gateway nutzt `ref`, um das zugehörige FCM/APNS-Token nachzuschlagen und sendet den leeren "Wake-Up Ping" an das OS. Es protokolliert den `ref` nicht persistent.

### 5.6 Schutz vor Denial-of-Service (DoS Mitigation)

Da OATP-Relays öffentlich erreichbare Endpunkte sind, die Daten von anonymen Sendern akzeptieren, sind sie primäre Ziele für Flooding- und Resource-Exhaustion-Angriffe. Um die Verfügbarkeit des Netzwerks zu sichern, MÜSSEN Relays die folgenden Schutzmechanismen implementieren.

#### 5.6.1 Normatives Rate-Limiting (Token Bucket)
Jedes Relay MUSS einen **Token Bucket Filter** für eingehende Schreibzugriffe (`POST`) implementieren.

*   **Algorithmus:** Für jeden Request wird ein Token aus dem Bucket entfernt. Ist der Bucket leer, wird der Request mit HTTP Status **`429 Too Many Requests`** abgelehnt.
*   **Scope:** Das Limit SOLLTE pro `inbox_id` angewendet werden. Für die erste Nachricht an eine neue Inbox (wo noch kein Traffic-Profil existiert) KANN das Limit auf IP-Basis angewendet werden.
*   **Standard-Parameter:**
    *   **Kapazität (Burst):** **100 Token**. Dies erlaubt das sofortige Senden von ca. 20 Nachrichten (bei $N=5$).
    *   **Refill-Rate (Sustained):** **1 Token pro Sekunde**.
*   **Implementierungshinweis:** Relays DÜRFEN diese Werte konfigurierbar machen, SOLLTEN aber niemals unlimitierten Zugriff gewähren.

#### 5.6.2 Proof-of-Work (Hashcash)
Wenn ein Relay unter hoher Last steht oder ein Client das Rate-Limit überschreitet, KANN das Relay dynamisch einen Arbeitsnachweis (PoW) anfordern.

*   **Header:** Der Client muss den Header `X-OATP-PoW` im Request mitsenden.
*   **Algorithmus:** OATP standardisiert **Hashcash** (SHA-256).
*   **Format:** `1:<bits>:<timestamp>:<inbox_id>:<random_nonce>`
    *   `bits`: Die geforderte Schwierigkeit (Anzahl führender Null-Bits).
    *   `timestamp`: UNIX-Timestamp (Gültigkeitsfenster z.B. +/- 10 Min).
    *   `inbox_id`: Bindet den PoW an das Ziel (verhindert Replay für andere Inboxes).
*   **Schwierigkeit:**
    *   **Basis:** 20 Bits (benötigt < 1 Sekunde auf modernen Smartphones).
    *   **Eskalation:** Relays KÖNNEN die Difficulty unter Last erhöhen.
*   **Validierung:** `SHA256(HeaderString)` muss `< 2^(256-bits)` sein.

#### 5.6.3 Begrenzung der Shard-Größe
Um Memory-Exhaustion-Angriffe zu verhindern, bei denen Angreifer riesige JSON-Objekte senden, um den Parser des Servers zum Absturz zu bringen, gilt ein hartes Limit.

*   **Vorschrift:** Die maximale Größe des HTTP-Body für `POST /inbox` (inklusive aller JSON-Overheads und Base64-Kodierung) ist normativ auf **128 KB** (131.072 Bytes) begrenzt.
*   **Konsequenz:** Größere Datenpakete MÜSSEN vom Sender auf Layer 2 (vor der OATP-Verpackung) in mehrere OATP-Nachrichten aufgeteilt werden ("Application Layer Chunking"). Requests, die das Limit überschreiten, MÜSSEN vom Relay mit **`413 Payload Too Large`** abgelehnt werden, idealerweise bevor der gesamte Body eingelesen wurde (Streaming Check).

---

**Section 6: Delivery Reliability**

## 6. Zustellgarantie und Zuverlässigkeit (Delivery Reliability)

Da OATP auf einem "Best Effort"-Netzwerk aus unvertrauenswürdigen Relays und fragmentierten Datenpaketen basiert, ist die Bestätigung der erfolgreichen Zustellung nicht trivial. OATP implementiert Zuverlässigkeit nicht auf der Transportebene (TCP-ACKs reichen nicht), sondern auf der **Ende-zu-Ende-Ebene**.

### 6.1 Acknowledgements (Empfangsbestätigungen)

OATP unterscheidet strikt zwischen **Transport-Bestätigungen** (Server hat Daten erhalten) und **Protokoll-Bestätigungen** (Agent hat Daten verarbeitet).

#### 6.1.1 Relay Response (Hop-by-Hop)
Wenn ein Sender einen Shard bei einem Relay einwirft, erhält er einen HTTP-Statuscode (z.B. `201 Created`).
*   **Bedeutung:** "Das Relay hat den Shard gespeichert."
*   **Grenze:** Dies garantiert NICHT, dass der Empfänger den Shard abholen kann oder dass das Relay ehrlich ist. Es dient lediglich dem Retry-Handling des Uploads.

#### 6.1.2 Delivery Receipt (End-to-End)
Die einzig verlässliche Bestätigung ist der **Delivery Receipt** vom Empfänger-Agenten.
*   **Trigger:** Sobald der Empfänger genügend Shards ($K$) gesammelt hat, den Container erfolgreich rekonstruiert (Reed-Solomon Decode) und die kryptografische Integrität (AEAD Tag) verifiziert hat, MUSS er einen Receipt generieren.
*   **Format:** Der Receipt ist technisch eine neue, sehr kleine OATP-Nachricht, die an den Sender zurückgeschickt wird.
*   **Inhalt:**
    ```json
    {
      "type": "https://w3id.org/oatp/v1/DeliveryReceipt",
      "ack_for_seq": 42,       // Sequenznummer der empfangenen Nachricht
      "timestamp": "2026-11-23T14:35:00Z"
    }
    ```
*   **Sicherheit:** Der Receipt MUSS verschlüsselt und signiert sein wie jede andere Nachricht auch. Dies beweist dem Sender, dass der Empfänger im Besitz des privaten Schlüssels ist und die Nachricht lesen konnte.

**Abgrenzung:** Ein `DeliveryReceipt` bestätigt die **technische Zustellung**. Es ist KEINE "Lesebestätigung" (Read Receipt) auf UI-Ebene. Ob der Nutzer die Nachricht gesehen hat, wird auf Layer 2 (z.B. im Messenger-Protokoll) geregelt.

### 6.2 Retry Logic (Wiederholungsstrategien)

Was passiert, wenn kein Receipt eintrifft? OATP definiert Strategien, um Netzwerk-Spam zu vermeiden und dennoch Zustellung zu sichern.

#### 6.2.1 Timer-basierter Retry
Der Sender startet nach dem Versand aller Shards einen Timer (z.B. `ExpectedLatency * 2`). Läuft dieser ab, ohne dass ein Receipt eintrifft, geht der Sender in den Retry-Modus.

#### 6.2.2 Exponentielles Backoff
Um das Netzwerk nicht zu fluten, MÜSSEN Sender bei fehlgeschlagenen Zustellversuchen ein exponentielles Backoff anwenden (z.B. Wiederholung nach 1 Min, 5 Min, 15 Min, 1 Std).

#### 6.2.3 Relay Rotation
Es ist sinnlos, dieselben Shards immer wieder an dasselbe (möglicherweise zensierende oder ausgefallene) Relay zu senden.
*   **Strategie:** Beim Retry SOLLTE der Sender alternative Relays aus dem DID Document des Empfängers wählen, sofern verfügbar.

### 6.3 Adaptive Redundancy (Inkrementelle Reparatur)

Ein besonderer Vorteil des Erasure Codings ist die Möglichkeit der inkrementellen Reparatur.
Szenario: Sender schickte 5 Shards ($N=5, K=3$). Empfänger hat nur 2 Shards erhalten (einer zu wenig).

*   **Ineffizient:** Sender schickt alle 5 Shards noch einmal.
*   **OATP-Weg (Smart Repair):** Der Sender generiert aus dem ursprünglichen Container **neue** Shards (z.B. Index 6 und 7). Er sendet nur diese zusätzlichen Paritäts-Fragmente.
    *   *Vorteil:* Der Empfänger kann die bereits empfangenen 2 Shards mit dem neuen Shard kombinieren, um auf $K=3$ zu kommen. Bandbreite wird gespart.

### 6.4 Erkennung von Duplikaten und Replay-Schutz (Duplicate Handling)

Aufgrund der asynchronen Natur des Netzwerks, der Retry-Logik des Senders und potenzieller Angriffe ist es unvermeidbar, dass ein Empfänger dieselben Daten mehrfach erhält. OATP definiert einen zweistufigen Prozess, um Duplikate effizient zu verwerfen und Replay-Attacken zu verhindern.

#### 6.4.1 Stufe 1: Shard-Deduplizierung
Empfänger MÜSSEN eingehende Shards anhand ihrer einzigartigen ID filtern, bevor sie gespeichert werden.
*   **Identifikator:** Die Kombination aus `msg_id` und `idx` (Index) aus dem entschlüsselten *Shard Bundle*.
*   **Prüfung:** Wenn für eine noch nicht rekonstruierte Nachricht bereits ein Shard mit demselben Index vorliegt, MUSS das Duplikat verworfen werden. Dies spart Speicherplatz im Staging-Bereich.

#### 6.4.2 Stufe 2: Nachrichten-Replay-Cache (Normativ)
Um zu verhindern, dass ein Angreifer alte, valide Shards (vor Ablauf der TTL) erneut sendet, um die Anwendung zu triggern (z.B. doppelte Bestellung), MÜSSEN Empfänger einen persistenten **Replay-Cache** führen.

*   **Inhalt:** Der Cache speichert die `msg_id` (Hash des Container-IVs) aller erfolgreich verarbeiteten Nachrichten.
*   **Timing der Prüfung:** Die Prüfung gegen den Cache MUSS **nach** der Entschlüsselung des Shard-Bundles (billig), aber zwingend **vor** der Reed-Solomon-Rekonstruktion (teuer) erfolgen.
    *   *Regel:* Wenn die `msg_id` eines eingehenden Shards bereits im Replay-Cache existiert, MUSS der gesamte Verarbeitungsprozess für diesen Shard abgebrochen werden. Er wird nicht gespeichert und triggert keinen RS-Decode.
*   **Reaktion (Idempotenz):** Obwohl die Nachricht verworfen wird, deutet ein Duplikat oft darauf hin, dass der ursprüngliche *Delivery Receipt* verloren ging (was den Retry des Senders auslöste). Der Empfänger SOLLTE daher (mit Rate-Limiting) erneut einen `DeliveryReceipt` für diese `msg_id` senden, ohne die Nachricht erneut an Layer 2 zu übergeben.

#### 6.4.3 Retention Policy (Speicherdauer)
Der Replay-Cache darf nicht unendlich wachsen. Einträge können sicher gelöscht werden, wenn die Nachricht aufgrund ihres Alters ohnehin ungültig wäre.
*   **Ablaufdatum:** `Expiry = created_timestamp + ttl` (aus den Metadaten des Containers).
*   **Bereinigung:** Einträge im Replay-Cache MÜSSEN mindestens so lange vorgehalten werden, bis dieses Ablaufdatum erreicht ist. Shards, die nach diesem Datum eintreffen, werden bereits durch die Zeit-Prüfung in Abschnitt 3.4 verworfen, sodass der Cache-Eintrag nicht mehr nötig ist.

---

**Section 7: Security Considerations**

## 7. Sicherheitsbetrachtungen (Security Considerations)

OATP operiert in einer Umgebung, in der die Transport-Infrastruktur (Relays) als **unvertrauenswürdig (untrusted)** eingestuft wird. Das Sicherheitsmodell muss daher garantieren, dass selbst ein bösartiges oder kompromittiertes Relay weder den Inhalt lesen noch die Kommunikation effektiv zensieren oder deanonymisieren kann.

### 7.1 Metadaten-Schutz und Traffic Analysis

Während die Inhaltsverschlüsselung (Kapitel 3) heute als gelöstes Problem gilt, stellen Metadaten ("Wer spricht mit wem?") die größte Angriffsfläche dar. OATP minimiert diese Fläche, kann sie aber auf Protokollebene nicht vollständig eliminieren.

#### 7.1.1 IP-Exposition und Transport
*   **Problem:** Jedes Relay muss auf TCP/IP-Ebene die IP-Adresse des Senders (beim `POST`) und des Empfängers (beim `GET`) kennen, um die Verbindung aufzubauen. Ein globaler Beobachter (Global Passive Adversary) oder ein kollusives Relay-Netzwerk könnten Zeitkorrelationen nutzen, um Sender und Empfänger zu verknüpfen.
*   **Mitigation:**
    *   **Blind Inboxes:** Da Inbox-IDs zufällige Hashwerte sind und keine DIDs, kann ein Relay eine IP-Adresse nicht trivial einer digitalen Identität zuordnen, sofern die DID nicht anderweitig geleakt wurde.
    *   **Transport-Verschleierung:** Agenten mit hohem Schutzbedarf MÜSSEN den Zugriff auf Relays über Anonymisierungsnetzwerke (Tor, I2P) oder VPN-Ketten tunneln. OATP-Implementierungen SOLLTEN SOCKS5-Proxy-Support nativ anbieten.

#### 7.1.2 Timing Attacks & Correlation
*   **Problem:** Wenn Agent A einen Shard sendet und Agent B diesen Millisekunden später abruft, entsteht ein zeitliches Muster.
*   **Mitigation (Asynchronität):** OATP ist als asynchrones Protokoll konzipiert. Empfänger SOLLTEN ihre Abruf-Intervalle randomisieren (Jitter) oder konstante Abrufraten nutzen, um Korrelationen zu erschweren. Die sofortige Zustellung via Push ("Wake-Up Ping") ist ein Trade-off zwischen Latenz und Privatsphäre.

#### 7.1.3 Padding (Größen-Korrelation)
*   **Vorschrift:** Alle Shards und Container MÜSSEN auf standardisierte Blockgrößen gepaddet werden (siehe Kapitel 3.3.1). Ein Relay darf nicht unterscheiden können, ob ein Shard Teil einer kurzen Textnachricht oder eines großen Bildes ist.

### 7.2 Spam & Denial-of-Service (DoS) Mitigation

Öffentliche, anonyme Einwurf-Boxen (Blind Inboxes) sind attraktiv für Spam und Flooding-Attacken. OATP implementiert ökonomische und kryptografische Hürden ("Backpressure").

#### 7.2.1 Infrastruktur-Schutz (Relay-Ebene)
Um die Verfügbarkeit der Relays zu sichern, kommen die in **Abschnitt 5.6** definierten Mechanismen zum Einsatz:
*   **Rate Limiting:** Der normative Token Bucket verhindert, dass einzelne Sender ein Relay überlasten.
*   **Proof-of-Work:** Der Hashcash-Header (`X-OATP-PoW`) macht Spam rechnerisch teuer.
*   **Größenlimits:** Die Begrenzung auf 128 KB pro Shard verhindert Memory-Exhaustion-Angriffe.

#### 7.2.2 Inbox Rotation (Empfänger-Ebene)
*   **Secret Inbox ID:** Die `inbox_id` ist ein Geheimnis (Capability). Wer die ID nicht kennt, kann nichts einwerfen.
*   **Rotation:** Wenn eine Inbox "verbrannt" ist (z.B. durch Spam geflutet, trotz Relay-Schutz), generiert der Empfänger eine neue ID und teilt diese seinen legitimen Kontakten via OAEP mit (siehe 5.1.4). Die alte Inbox wird beim Relay gelöscht oder ignoriert.

### 7.3 Forward Secrecy & Key Management

Die Sicherheit von OATP hängt direkt von der Sicherheit der Schlüssel aus dem OAEP-Layer ab.

*   **PFS-Vererbung:** Da OATP die `Session Keys` aus dem OAEP-Handshake nutzt (welcher Ephemeral Diffie-Hellman verwendet), erbt OATP die Eigenschaft der **Perfect Forward Secrecy** gemäß **OAEP v1.0**. Wird ein Gerät später beschlagnahmt, können aufgezeichnete alte OATP-Shards nicht entschlüsselt werden, da die Sitzungsschlüssel gelöscht wurden.
*   **Löschpflicht:**
    *   **Sender:** MUSS den Klartext und den verschlüsselten Container sofort nach dem Sharding aus dem Arbeitsspeicher entfernen.
    *   **Empfänger:** MUSS die empfangenen Shards unwiderruflich löschen, sobald der Container erfolgreich rekonstruiert wurde.
    *   **Relay:** MUSS Shards nach Ablauf der TTL oder nach explizitem `DELETE`-Befehl physisch löschen.

### 7.4 Unlesbarkeit der Fragmente

Ein einzelner Shard (oder auch eine Menge von $K-1$ Shards) enthält theoretisch und praktisch **null Information** über den Inhalt der Nachricht.
*   **Verschlüsselung:** Da bereits die Metadaten des Shards (`msg_id`, `idx`) gemäß Abschnitt 4.2.3 AEAD-verschlüsselt sind, sieht ein Angreifer, der ein Relay kompromittiert, nur uniforme Zufallsdaten.
*   **Zensur-Resistenz:** Ein Relay kann nicht selektiv Fragmente bestimmter Nachrichten oder Absender blockieren, da es keine Unterscheidungsmerkmale gibt ("All or Nothing").

### 7.5 Integrität der Fragmente (Shard Corruption Detection)

Ein böswilliges Relay könnte versuchen, gespeicherte Shards zu manipulieren (Bit-Flip), um die Rekonstruktion der Nachricht beim Empfänger zu verhindern ("Pollution Attack"). OATP v1.0 begegnet diesem Risiko durch eine mehrstufige Integritätsprüfung.

1.  **Primäre Prüfung (Shard-Level):**
    Da das *Shard Bundle* gemäß Abschnitt 4.2.3 mit einem AEAD-Verfahren (ChaCha20-Poly1305) verschlüsselt ist, besitzt jeder einzelne Shard einen kryptografischen **Authentication Tag**.
    *   **Vorschrift:** Empfänger MÜSSEN beim Entschlüsseln des `data`-Feldes im Relay-Envelope zwingend den Auth-Tag validieren.
    *   **Konsequenz:** Schlägt die Validierung fehl, wurde der Shard manipuliert oder beschädigt. Der Shard MUSS sofort verworfen werden und DARF NICHT in den Reed-Solomon-Prozess einfließen.

2.  **Sekundäre Prüfung (Container-Level):**
    Sollte ein Shard technisch valide entschlüsselt werden, aber logisch inkonsistente Daten enthalten (z.B. durch einen Fehler beim Sender), greift die Integritätsprüfung des rekonstruierten JWE-Containers (siehe 3.4). Stimmt dessen AEAD-Tag nicht, ist die Rekonstruktion gescheitert.

3.  **Blacklisting (Reputation):**
    Ein Relay, das einen Shard mit ungültigem AEAD-Tag ausliefert, hat entweder einen Speicherfehler oder agiert böswillig. Clients SOLLTEN solche Relays temporär auf eine Blockliste setzen, um Bandbreite nicht an unzuverlässige Knoten zu verschwenden.
    
---

**Section 8: Implementation Guidelines**

## 8. Richtlinien für Implementierer (Implementation Guidelines)

Die Implementierung von OATP, insbesondere auf mobilen Endgeräten, erfordert ein sorgfältiges Ressourcenmanagement. Ein "naives" Design, das für jeden Shard eine eigene TCP-Verbindung öffnet, würde die Batterie eines Smartphones in kürzester Zeit entleeren und zu schlechter User Experience führen.

Dieses Kapitel definiert Best Practices und architektonische Muster, die für eine produktionsreife OATP-Bibliothek (SDK) empfohlen werden.

### 8.1 Batching & Netzwerkeffizienz

Das Versenden einer einzigen Nachricht im Standard-Schema $(N=5)$ erzeugt 5 ausgehende HTTP-Requests. Um den Overhead (TLS-Handshake, Header) zu minimieren, SOLLTEN Implementierungen Batching-Strategien nutzen.

#### 8.1.1 Outgoing Batching (Nagle's Algorithm für Shards)
Wenn ein Agent mehrere Nachrichten kurz hintereinander sendet (z.B. Chat-Nachrichten) oder eine große Datei (in viele Shards zerlegt) überträgt:
*   **Strategie:** Der OATP-Client SOLLTE ausgehende Shards, die an *dasselbe* Relay adressiert sind, für ein kurzes Zeitfenster (z.B. 50-200ms) in einer Queue sammeln.
*   **Bulk-API:** Relays MÜSSEN einen Endpunkt für Batch-Operationen anbieten (z.B. `POST /v1/batch/inbox`), der ein Array von Shards in einem einzigen Request akzeptiert.
*   **Vorteil:** Reduktion der RTT (Round Trip Time) und CPU-Last auf beiden Seiten.

#### 8.1.2 Parallelität beim Download
Beim Empfang ist Latenz der kritische Faktor.
*   **Parallel Fetch:** Der Empfänger SOLLTE versuchen, Shards von verschiedenen Relays parallel herunterzuladen.
*   **Racing:** Sobald $K$ Shards erfolgreich geladen wurden, SOLLTE der Rekonstruktionsversuch gestartet werden. Laufende Downloads der verbleibenden $N-K$ Shards KÖNNEN abgebrochen werden, sobald die Integrität des Containers verifiziert ist, um Bandbreite zu sparen.

### 8.2 Offline-Handling & Die "Local Outbox"

OATP ist ein "Store-and-Forward"-Protokoll. Die Netzwerkschicht muss davon ausgehen, dass das Gerät zum Zeitpunkt des Sendens offline ist.

#### 8.2.1 Persistente Warteschlange (Queue)
Implementierungen DÜRFEN Nachrichten NICHT nur im RAM halten.
1.  **Persistenz:** Bevor der Sende-Versuch unternommen wird, MUSS der verschlüsselte Container und seine Shards in eine lokale, persistente Datenbank (z.B. SQLite, LevelDB) geschrieben werden.
2.  **State Management:** Jeder Shard in der Outbox hat einen Status (`PENDING`, `SENT`, `FAILED`).
3.  **Hintergrund-Synchronisation:** Ein Background-Worker (z.B. Android WorkManager, iOS BackgroundTasks) arbeitet die Queue ab, sobald Konnektivität besteht.

#### 8.2.2 Intelligentes Retry (Backoff)
Wenn ein Relay nicht erreichbar ist:
*   **Kein Busy-Loop:** Es darf kein sofortiger, dauerhafter Retry erfolgen.
*   **Exponential Backoff:** Die Wartezeit zwischen Versuchen muss exponentiell steigen (1s, 2s, 4s, 8s...), um Batterie zu sparen und Server nicht zu überlasten.
*   **Circuit Breaker:** Wenn ein Relay dauerhaft Fehler liefert (z.B. 5xx Codes), SOLLTE es temporär auf eine interne "Sick List" gesetzt und für neue Nachrichten gemieden werden (siehe Relay Rotation in Kap. 6.2.3).

### 8.3 Push Notifications (Das "Wake-Up" Problem)

Auf modernen mobilen Betriebssystemen (iOS, Android) können Apps keine dauerhaften Hintergrundverbindungen halten. Sie werden vom OS "eingefroren". Um Nachrichten in Echtzeit zu empfangen, ist ein externer Trigger notwendig.

Da OATP Relays den Inhalt nicht kennen, können sie keine "Rich Notifications" (mit Textvorschau) senden. Dies ist ein Feature, kein Bug ("Privacy by Design").

#### 8.3.1 Der "Empty Ping" Flow
1.  **Registrierung:** Der Empfänger-Agent registriert sich beim Push-Dienst des OS (APNS/FCM) und hinterlegt das Token beim Relay (indirekt über das Gateway-Protokoll, siehe 5.5.5).
2.  **Signal:** Trifft ein Shard ein, sendet das Relay nur ein Signal: "Neue Daten für Handle X". Dieses Signal enthält **keine** Nutzdaten.
3.  **Aufwecken (iOS Notification Service Extension):**
    *   Unter iOS nutzt die App eine *Notification Service Extension*.
    *   Das OS weckt die Extension für kurze Zeit (ca. 30 Sek.) im Hintergrund.
    *   Die Extension verbindet sich mit dem Relay, lädt die Shards, rekonstruiert und entschlüsselt den Container.
4.  **Lokale Anzeige:** Erst *nach* der lokalen Entschlüsselung generiert die App die sichtbare Benachrichtigung ("Neue Nachricht von Anna: Hallo!").
5.  **Vorteil:** Apple/Google sehen nur, *dass* eine Benachrichtigung kam, aber niemals den Inhalt oder den Absender.

#### 8.3.2 UnifiedPush (Android Alternative)
Für Android-Nutzer ohne Google Play Services (z.B. Th!nkOS, GrapheneOS) SOLLTE die Bibliothek den offenen Standard **UnifiedPush** unterstützen. Dies ermöglicht die Nutzung von selbstgehosteten Push-Servern (z.B. ntfy), wodurch die Abhängigkeit von Google FCM komplett entfällt.

### 8.4 Speicher-Management & Garbage Collection

Da OATP-Clients Datenfragmente (Shards) lokal zwischenspeichern müssen – sowohl eingehend (zur Rekonstruktion) als auch ausgehend (für Retries) – wächst der Speicherbedarf dynamisch an. Ohne striktes Management könnte ein Angreifer den Speicher eines Geräts füllen, indem er unvollständige Fragment-Sets sendet.

#### 8.4.1 Ephemeral Inbound Storage (Eingehend)
Eingehende Shards sind nur Mittel zum Zweck.
*   **Immediate Cleanup:** Sobald $K$ Shards empfangen wurden und der Message Container erfolgreich rekonstruiert und validiert (AEAD Tag Check) wurde, MÜSSEN alle Shards, die zu dieser `msg_id` gehören, **sofort** physisch vom Speicher gelöscht werden.
*   **Deduplizierung:** Trifft ein Shard ein, für dessen `msg_id` die Nachricht bereits rekonstruiert wurde, MUSS der Shard verworfen werden.

#### 8.4.2 Das "Orphan"-Problem (Adaptive Garbage Collection)
Ein Angreifer könnte gezielt unvollständige Sets von Shards (z.B. immer nur $K-1$ Stück) an einen Empfänger senden. Diese Fragmente können niemals zu einer Nachricht rekonstruiert werden, belegen aber Speicherplatz im Staging-Bereich. Ein rein statischer Timeout würde es einem Angreifer ermöglichen, den Speicher des Geräts dauerhaft zu blockieren ("Storage Exhaustion DoS").

Um dies zu verhindern, MÜSSEN Implementierungen eine **Adaptive Garbage Collection** basierend auf dem Füllstand des zugewiesenen Speichers (Quota) realisieren:

1.  **Basis-Timeout (Normalbetrieb):** Solange die Speicherauslastung unter einem Schwellenwert (Empfehlung: **80%**) liegt, gilt der Standard-Timeout `MAX_REASSEMBLY_TIME` von **24 Stunden**.
2.  **Aggressive Bereinigung (Hochlast):** Steigt die Auslastung über 80%, MUSS der Timeout für *neue und existierende* unvollständige Sets drastisch reduziert werden (Empfehlung: **1 Stunde**). Dies zwingt Angreifer dazu, ihre Angriffsrate massiv zu erhöhen, was wiederum durch Rate-Limiting erkannt werden kann.
3.  **Panic Mode (Kritisch):** Steigt die Auslastung über einen kritischen Wert (Empfehlung: **95%**), MUSS das System in den **LRU-Modus (Least Recently Used)** wechseln. Dabei werden die ältesten unvollständigen Fragment-Sets sofort gelöscht, um Platz für neue Daten zu schaffen, unabhängig von ihrem Alter.
4.  **Concurrency Limit:** Zusätzlich SOLLTE die Anzahl der gleichzeitig offenen, unvollständigen Nachrichten pro `inbox_id` limitiert werden (z.B. max. 50 pending messages).

#### 8.4.3 Outbox Management (Ausgehend)
Gesendete Nachrichten müssen für potenzielle Retries (siehe Kap. 6.2) vorgehalten werden.
*   **Lösch-Trigger:** Shards DÜRFEN erst aus der lokalen Datenbank gelöscht werden, wenn:
    1.  Ein kryptografisch valider **Delivery Receipt** (Kap. 6.1.2) vom Empfänger eingetroffen ist.
    2.  ODER der Nutzer die Nachricht manuell löscht.
    3.  ODER der globale `MESSAGE_EXPIRY_TIMEOUT` (z.B. 14 Tage) überschritten wurde.

#### 8.4.4 Storage Quotas & Eviction
Um die Stabilität des Betriebssystems zu gewährleisten, SOLLTEN OATP-Bibliotheken ein Speicherlimit (Quota) respektieren.
*   **LRU Eviction:** Wird der Speicher knapp, SOLLTE der Client die ältesten, unvollständigen Fragment-Sets ("Orphans") vorzeitig löschen.
*   **Priorisierung:** Die Outbox (eigene, gesendete Nachrichten) SOLLTE eine höhere Priorität beim Speichererhalt haben als die Inbound-Staging-Area.

### 8.5 Interoperabilität im Code (SDK Design)

Das OAP-SDK sollte die Komplexität von Erasure Coding und Networking kapseln.

*   **Empfohlene Abstraktion:** Entwickler der Anwendungsschicht (Layer 2) sollten nur eine Methode aufrufen:
    `messenger.send(recipient_did, payload_json)`
*   **Under the Hood:** Das SDK übernimmt autonom:
    1.  OAEP-Handshake / Session Lookup.
    2.  JWE-Verschlüsselung.
    3.  Reed-Solomon-Encoding.
    4.  Relay-Auswahl und Upload.
    5.  Retry-Management.
*   **Events:** Das SDK sollte Events emittieren (`onProgress`, `onDelivered`, `onRead`), damit die UI (z.B. Haken im Chat) reaktiv aktualisiert werden kann.

### 8.6 Strategie für mehrere Endgeräte (Multi-Device Strategy)

In der Praxis nutzen User häufig mehrere Geräte (z.B. Smartphone und Laptop) parallel. Da OATP keinen zentralen "Sync-Server" besitzt, muss die Synchronisation der Nachrichten durch die Architektur gelöst werden.

#### 8.6.1 Das "Shared Inbox" Anti-Pattern
Es wird DRINGEND davon abgeraten, dieselbe `inbox_id` auf mehreren Geräten gleichzeitig zu verwenden.
*   **Race Condition:** Wenn Gerät A die Nachrichten abruft und gemäß Protokoll löscht (`DELETE`), sind die Daten für Gerät B unwiderruflich verloren, bevor es synchronisieren konnte.
*   **Status-Konflikte:** Die Verwaltung von Nonce-Caches und Replay-Schutz wird bei geteilten Inboxes extrem komplex und fehleranfällig.

#### 8.6.2 Device-Specific Inboxes (Empfohlen)
Die korrekte Strategie in OATP v1.0 ist die Verwendung dedizierter Inboxes pro Gerät.
1.  **Registrierung:** Jedes Gerät des Nutzers registriert im gemeinsamen DID Document einen eigenen Service-Endpoint (z.B. `#mobile-inbox` und `#desktop-inbox`).
2.  **Sender-Verhalten (Client-Side Fan-Out):**
    Der Sender analysiert das DID Document des Empfängers. Findet er mehrere valide `OAPEndpoint`-Einträge, MUSS er die Nachricht (bzw. deren Shards) an **alle** diese Endpunkte senden.
    *   *Hinweis:* Dies erhöht den Traffic-Aufwand für den Sender linear mit der Anzahl der Empfänger-Geräte, garantiert aber eine zuverlässige Zustellung ohne Server-Logik.
3.  **Unabhängigkeit:** Jedes Empfänger-Gerät verwaltet seinen eigenen Abruf- und Löschzyklus völlig autonom.

### 8.7 Flusskontrolle (Flow Control - Informativ)

In OATP v1.0 existiert noch kein protokoll-interner, normativer Mechanismus für **End-to-End Flow Control** (z.B. Sliding Windows zur Signalisierung von Backpressure zwischen Agenten). Dies ist ein geplantes Feature für OATP v1.1.

Um Ressourcenerschöpfung bei asymmetrischen Verbindungen (z.B. Desktop sendet an IoT-Gerät) in v1.0 zu vermeiden, gelten folgende Richtlinien:

1.  **Transport-Layer Backpressure:** Sender MÜSSEN strikt auf die HTTP-Statuscodes der Relays reagieren. Ein `429 Too Many Requests` oder `507 Insufficient Storage` ist ein hartes Signal, die Senderate sofort zu drosseln.
2.  **Application-Layer Throttling:** Die Anwendungsschicht (Layer 2) darf OATP nicht als "Firehose" betrachten. Implementierungen SOLLTEN die Anzahl der **"In-Flight"-Nachrichten** (gesendet, aber noch kein *Delivery Receipt* erhalten) pro Empfänger intern begrenzen (Empfehlung: max. 50 unbestätigte Nachrichten). Wird dieses Limit erreicht, sollte der `send()`-Aufruf blockieren oder fehlschlagen.
3.  **Notbremse:** Empfänger, die von einem Sender überflutet werden, KÖNNEN weitere Nachrichten dieses Senders temporär stillschweigend verwerfen (Silent Drop) oder – als ultima ratio – die `inbox_id` rotieren, um den Datenstrom physikalisch zu unterbrechen.

---

**Section 9: Appendix & Examples**

## 9. Anhang und Beispiele (Appendix & Examples)

Dieser Abschnitt ist informativ. Er stellt Beispiele für den Lebenszyklus einer Nachricht, JSON-Payloads und eine formale API-Definition bereit.

### 9.1 End-to-End Nachrichtenfluss (Beispiel)

Szenario: Alice (Sender) sendet eine OACP-Bestellung an Bob (Empfänger).
*   **OAEP-Status:** `ACTIVE`. Sitzungsschlüssel (`Client_Write_Key`) sind ausgehandelt.
*   **Sharding-Parameter:** $N=5, K=3$.
*   **Sequenz:** Dies ist die 42. Nachricht in dieser Session (`seq = 42`).

#### Schritt 1: Payload Erstellung
Alice erstellt das JSON-LD Objekt (Layer 2).
```json
// Plaintext
{
  "meta": {
    "type": "https://w3id.org/oacp/v1/OrderRequest",
    "created": "2026-11-23T14:30:00Z",
    "ttl": 86400
  },
  "data": { "offerId": "uuid-123", "product": "Th!nkPhone" },
  "padding": "a8f3... (zufällige Bytes bis Blockgröße 256)"
}
```

#### Schritt 2: Verschlüsselung (Containerisierung)
Alice bereitet den JWE-Header vor und leitet die Nonce ab.

1.  **Header:** `{"alg":"dir", "enc":"C20P", "seq":42, "kid":"a1b2c3d4..."}`.
2.  **Nonce-Ableitung:** Alice berechnet die Nonce mittels HKDF (siehe 3.3.3):
    `Nonce = HKDF(Key, Info="OATP-Nonce-v1" || 0x000000000000002A, L=12)`.
3.  **Verschlüsselung:** Sie verschlüsselt den Plaintext mit `ChaCha20-Poly1305` unter Verwendung des abgeleiteten IVs.
4.  **Resultat:** Ein JWE Compact String.
    `eyJhbGciOiJkaXIiLCJlbmMiOiJDMjBQ... (Header)..ivBase64.ciphertextBase64.tagBase64`

#### Schritt 3: Sharding (Erasure Coding)
Der verschlüsselte Container (sagen wir 1000 Bytes) wird gepaddet (auf ein Vielfaches von $K=3$, also 1002 Bytes) und in 3 Daten-Chunks zerlegt. Der Reed-Solomon-Encoder (GF(2^8), Polynom 0x11D) generiert 2 zusätzliche Paritäts-Chunks.
*   **Ergebnis:** 5 Shards.

#### Schritt 4: Distribution
Alice verpackt jeden Shard in einen verschlüsselten Relay-Envelope (inkl. `shard_id` und verschlüsselter `msg_id`) und sendet sie an 5 unterschiedliche Relays (R1 bis R5).
*   `POST https://relay1.com/v1/inbox/{blind_hash_1}` -> Body: Shard 1 Envelope
*   ...

#### Schritt 5: Empfang & Rekonstruktion
Bob pollt die Relays.
1.  Er lädt Shard 1, 3 und 5 erfolgreich herunter.
2.  Da $3 \ge K$, startet er den RS-Decode und erhält den JWE-Container zurück.
3.  Er liest `seq=42` aus dem Header, leitet lokal dieselbe Nonce via HKDF ab.
4.  Er prüft den Auth-Tag (Integrität OK) und entschlüsselt den Payload.
5.  Er sendet einen `DeliveryReceipt` für `seq=42` zurück.

### 9.2 JSON Schemas (Relay API)

Für die Interoperabilität der Relay-Server wird hier die **OpenAPI 3.0 (Swagger)** Definition der Schnittstelle bereitgestellt.

```yaml
openapi: 3.0.0
info:
  title: OATP Relay API
  version: 1.0.0
  description: API definition for OATP Blind Relays (Layer 1)
paths:
  /v1/inbox/{inbox_id}:
    post:
      summary: Deliver a shard (Einwurf)
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
      summary: Retrieve shards (Abholung)
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

### 9.3 Kryptografische Test-Vektoren

Implementierer MÜSSEN ihre Sharding-Logik gegen diese Vektoren testen, um sicherzustellen, dass die Reed-Solomon-Implementierung binärkompatibel ist.

#### 9.3.1 Reed-Solomon (N=5, K=3)
*   **Algorithmus:** Reed-Solomon über GF(2^8) mit Polynom `0x11D` (Vandermonde Matrix).
*   **Input Data:** `48656c6c6f20576f726c6421` ("Hello World!")
    *   *Hinweis:* Input (12 Bytes) ist bereits durch 3 teilbar, kein Padding nötig.
*   **Erwartete Shards (Hex):**
    *   Shard 0 (Data): `48 65 6c 6c` ("Hell")
    *   Shard 1 (Data): `6f 20 57 6f` ("o Wo")
    *   Shard 2 (Data): `72 6c 64 21` ("rld!")
    *   Shard 3 (Parity): `55 bf 5f 22`
    *   Shard 4 (Parity): `e7 9a 31 d9`

*Test-Szenario:* Lösche Shard 0 und 1. Füttere Shard 2, 3 und 4 in den Decoder. Das Ergebnis MUSS wieder exakt `48656c6c6f20576f726c6421` sein.

### 9.4 Referenz-Implementierung

Die offizielle Referenzimplementierung der OAP Foundation befindet sich im Repository `oap-core-rs`.

*   **Crate:** `oatp::core`
*   **Modules:**
    *   `oatp::crypto::aead` (Verschlüsselung & HKDF)
    *   `oatp::coding::erasure` (Sharding Logic mit GF(2^8))
    *   `oatp::transport::relay` (HTTP Client/Server Stubs)

Entwickler werden angehalten, für kritische Anwendungen diese Rust-Bibliothek (oder ihre Bindings für Kotlin/Swift/JS) zu verwenden, anstatt den Sharding-Algorithmus selbst zu implementieren.

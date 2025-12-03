# Bet365-Reversed-VM
This is a repo containing documentation on the full reversal of the VM to figure out the AES logic behind the x-net-sync-term.
If you need to contact me, my telegram is @MovistarSucks


## Reverse‑engineering the “Netclass3” VM – technical walkthrough

### 1. Getting a clean disassembly
1) Extract the embedded base64 blob, decode to raw bytecode.
2) Fix the disassembler: CALL_ENTER operands are 2 bytes.
3) Emit an aligned listing (6k lines) Function entry points are discoverable from CALL_ENTER targets.
4) Search for clusters that look like they could be AES (Lot of XORs) and identify where we stand once we do.

### 2. Table decoding and AES artifacts
The loader at CALL_ENTER 24364:
- Splits CSV strings, XORs each byte with 0x7F.
- Populates arrays from long LD_STR_X57 constants.

  results:
- Te0..Te3 (256 × int32) — AES T‑tables.
- S‑box / inverse byte tables (256 × u8)
- A small GF helper table (256 × u8)

### 3. Key schedule (CALL_ENTER 25280 → 24980)
Hard-coded AES‑128 key words:
- w0 = 0x2d43590c
- w1 = 0x22384e5a
- w2 = 0x7bea2d43
- w3 = 0x590c2238
Bytes: "2d43590c22384e5a7bea2d43590c2238"

Expansion:
- Standard AES schedule using S‑box (r68) and RCON in r66.
- Fills 44 words into r0 (round keys), mirrored into r1 for reverse use.

### 4. Counter/IV derivation (CALL_ENTER 26560)
- Inputs: "cf4" string (from the VM’s “cf4” routine) and "r53" (first Math.random() * 2147483647).
- Hash function: FNV‑like, offset 2166136261, multiply 0x01000193 (implemented as add/shift).
- For idx = 0..3: hash("cf4 + idx + r53") → 32‑bit word (big‑endian).
- Concatenate 4 words → 16‑byte counter/IV, Counter increments big endian per block.

### 5. Block cipher core (CALL_ENTER 25844)
- Packs 16 bytes into 4 words.
- 9 T‑table rounds (Te tables r70/72/74/76) + final S‑box round (r68) with last round key.
- Returns `[input_block, keystream_bytes]`.

### 6. CTR wrapper (CALL_ENTER 26776)
- Inputs: counter block, data buffer.
- Encrypts counter → keystream, XORs into buffer, increments counter (big endian), repeats.
- Clears r0/r1 on exit to wipe round keys.

### 7. Where encryption is invoked
- Single observed call site: IP 62852 (~61548).
  - Builds counter via 26560 (cf4 + r53).
  - Builds plaintext via char‑map builder 24688.
  - Runs CTR wrapper; wraps ciphertext into CustomEvent "xcft" (and sometimes `gsm`) as `detail`.

### 8. Runtime capture
  - Wrap Math.random to log "r53", read "localStorage.cf4", rebuild counter with the same hash.
  - Listen for "xcft" events.

### 10. Pitfalls encountered
- CALL_ENTER width had to be fixed; otherwise disasm diverges.
- Patching the VM’s step function can crash the runtime; observing via Math.random + events is safer.
- The IV derivation does not use timestamp; only cf4 + r53 matter.

### 11. Why this is enough
- The AES key is static in bytecode.
- IV is deterministic from per‑session cf4 + r53.
- Ciphertext is emitted as event `detail`.
→ Capturing `r53`, `cf4`, counter, and ciphertext in one session is sufficient to decrypt all tokens from that session.

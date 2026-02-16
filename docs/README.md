# What is FROST?

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is a cryptographic protocol that lets a group securely share control of a single private key without anyone ever seeing or reconstructing the full key.

Participants start with distributed key generation (DKG): n people each create a share, ending up with one shared public key (just like a normal Schnorr key in Bitcoin or Nostr).

To sign a message, only a threshold (e.g., 3-out-of-5) collaborate. They exchange messages in just two rounds (hence "round-optimized"), then combine partial signatures into one valid Schnorr signature that looks identical to a single-person signature—no one can tell it was threshold-based.

This approach is more efficient and private than traditional multisig (which bloats data and exposes multiple keys) or basic secret sharing (which often requires a trusted dealer or risky full-key reconstruction).

Here's how the basic flow works visually:

![Two-round FROST signing protocol: signers send nonce commitments to a coordinator in round one, then produce partial signatures in round two which the coordinator combines into a single valid Schnorr signature](images/frost-signing-flow.png)

![FROST threshold diagram showing how t-of-n secret shares held by individual participants each produce partial signatures that combine to meet the signing threshold and form one complete Schnorr signature](images/frost-threshold-diagram.png)

![FROST key share distribution graph illustrating how a dealer or DKG distributes polynomial-derived shares to n participants, where any t participants can reconstruct signing capability without exposing the full secret](images/frost-key-sharing.png)

FROST is especially useful for Nostr because Nostr uses Schnorr keys for signing events (posts, zaps, etc.). Projects like Keep leverage FROST to enable shared or multisig Nostr accounts—letting friends or teams jointly control one profile without any single person holding the full key, perfect for group accounts or more resilient personal setups.

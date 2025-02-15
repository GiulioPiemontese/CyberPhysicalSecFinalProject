SANA Protocol - Overview
SANA (Secure Aggregation for Network Attestation) is a scalable, privacy-preserving attestation protocol designed for large-scale distributed networks (e.g., IoT, edge devices). It ensures that all devices in the network are running trusted software configurations without revealing individual device states.

🔹 How SANA Works
Setup Phase

The Owner generates RSA key pairs for each Prover and an Attestation Token.
The Verifier sends an attestation request (Ch) to the network.
Prover Response Generation

Each Prover computes a signature (α_i) over its software configuration.
If the configuration is trusted, the Prover signs a universal hash (h_g).
If untrusted, the Prover signs its actual configuration (h_i).
Aggregation Phase

Aggregators collect Prover signatures and aggregate them using Optimistic Aggregate Signatures (OAS).
This allows efficient batch verification instead of verifying each device individually.
Attestation & Verification

The root aggregator sends the aggregated signature (α_1) to the Verifier.
The Verifier checks whether the expected signature matches the aggregated response.
If a mismatch is found, compromised devices are identified.

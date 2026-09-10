⚡ Electric Money (EM)

«An experimental cryptocurrency protocol built around utility, predictable monetary policy, and community collaboration.»

Electric Money (EM) is an early-stage experimental cryptocurrency project.

The idea is simple: build a lightweight blockchain with a predictable monetary policy, Proof-of-Work mining, a small transaction receiver tax, an annual wallet balance tax, and a Treasury mechanism designed to redistribute collected funds to miners.

This project is still in an embryonic stage. The protocol, implementation, economics, networking and security model are all subject to further development, testing and review.

I'm publishing the project openly because I believe the idea has potential — and I'd like to find developers, researchers, miners and other people interested in helping build it.

If you like experimenting with blockchain protocols, you're very welcome to join. 🚀

---

🌱 Project Status

Experimental / Early Development

Electric Money is not production-ready and should not be considered a secure or mature cryptocurrency.

The current implementation is primarily intended for:

- experimentation
- protocol development
- security research
- testing
- economic simulations
- developer collaboration
- discussion and community feedback

Before any potential mainnet deployment, the project would require substantially more testing, independent security review, adversarial testing and protocol development.

---

💡 Core Idea

Electric Money attempts to combine several mechanisms into a single Proof-of-Work blockchain.

Main characteristics

- ⚡ Proof-of-Work blockchain
- ⏱️ 10-minute target block time
- ⛏️ Mining rewards with scheduled halvings
- 🔒 Hard maximum monetary supply
- 💸 0.25% receiver tax on incoming payments
- 📅 0.25% annual wallet balance tax
- 🏦 Monthly Treasury distribution
- ⚖️ Cumulative Proof-of-Work chain selection
- 🌐 Multi-node P2P architecture
- 🔄 Fork and reorganization handling
- 🧾 Deterministic blockchain replay
- 📦 Block and transaction size limits
- 🧪 Experimental Layer-2 commitment/sequencer architecture

---

💰 Monetary Policy

Electric Money has a fixed maximum cumulative issuance of:

72,270,024.841006 EM

The protocol uses integer base units to avoid floating-point consensus issues.

Block reward

The initial mining subsidy is:

25 EM per block

The mining subsidy is halved every:

1,445,400 blocks

With a target block time of approximately 10 minutes, this corresponds to approximately:

27.5 years per halving period

The reward eventually reaches zero after the scheduled halving sequence.

The supply cap is enforced by consensus based on total issued supply, rather than simply assuming that every block always receives the full subsidy.

---

💸 Transaction Receiver Tax

Electric Money currently applies a:

0.25% receiver tax

to incoming user payments.

The tax is deducted from the amount received and directed to the protocol Treasury.

This mechanism is intended to create a continuous source of Treasury funds without requiring a traditional centralized funding mechanism.

---

📅 Annual Wallet Balance Tax

Electric Money also includes an experimental:

0.25% annual wallet balance tax

The mechanism is deterministic and enforced during blockchain state transitions.

The goal is to explore an alternative economic model in which inactive or accumulated balances gradually contribute to the protocol Treasury.

This is one of the experimental economic components of Electric Money and is open to discussion, simulation and redesign.

---

🏦 Treasury

Collected protocol taxes accumulate in a Treasury.

The current design distributes the Treasury on a monthly basis.

Treasury distribution is based on verified Proof-of-Work mining activity during the relevant period.

The intention is to create an additional incentive for miners while recycling protocol-generated funds back into the network.

Treasury accounting is deterministic and part of blockchain state replay.

---

⛏️ Proof of Work

Electric Money uses Proof of Work as its consensus mechanism.

The blockchain tracks cumulative Proof-of-Work rather than simply choosing the chain with the greatest number of blocks.

This means that, in a fork, the protocol evaluates the accumulated computational work represented by competing chains.

The current implementation also contains an experimental mining-share system used to measure verified mining work for Treasury distribution.

Mining shares require actual Proof-of-Work verification and are tied to canonical mining jobs.

---

🌐 P2P Network

Electric Money includes a multi-node peer-to-peer implementation.

The current architecture supports:

- peer connections
- node handshakes
- transaction propagation
- block propagation
- chain synchronization
- orphan block handling
- fork detection
- heavier-chain adoption
- configurable peers
- node identities
- network limits

Networking is still under active development.

One of the major areas planned for future work is a more scalable and adversarially hardened synchronization protocol.

---

🔄 Chain Reorganizations

The node implementation supports competing chains and chain reorganizations.

The blockchain uses cumulative Proof-of-Work to determine the preferred chain.

When a heavier chain is discovered, the node can reorganize its local state around the new canonical chain.

Transactions from abandoned branches can be reconsidered for inclusion in the winning chain where appropriate.

Mining shares are associated with specific parent-chain contexts and are not blindly carried across reorganizations.

---

🧾 Deterministic Blockchain Replay

A core design principle of Electric Money is that blockchain state should be reproducible from the chain itself.

The implementation contains deterministic replay logic for:

- transactions
- balances
- nonces
- mining rewards
- Treasury accounting
- wallet taxation
- block validation
- issuance limits

This is important because a node should be able to reconstruct the expected state rather than blindly trusting persisted state.

---

📦 Consensus Limits

The protocol includes several resource limits intended to reduce abuse and denial-of-service risks.

Examples include limits for:

- block size
- transactions per block
- transaction age
- transaction amount
- future block timestamps
- orphan blocks
- P2P frame sizes
- connected peers
- pending mining shares

These limits are part of the ongoing security-hardening process.

---

🧪 Layer 2

Electric Money also contains an experimental Layer-2 architecture.

The current implementation should be understood as a:

sequencer / commitment layer

rather than a fully trustless rollup.

Layer-2 activity can be committed to the Layer-1 blockchain through deterministic commitments.

A future version could explore stronger proof systems and more trust-minimized settlement mechanisms.

---

🔐 Security

Security is one of the main areas of ongoing development.

The current codebase already contains several defensive mechanisms, including:

- deterministic state validation
- Proof-of-Work verification
- supply-cap enforcement
- transaction validation
- signature verification
- nonce validation
- block-size limits
- transaction-count limits
- timestamp restrictions
- median-time-past checks
- orphan limits
- P2P frame limits
- malformed-message handling
- chain replay
- fork/reorganization handling

However:

«Electric Money has not undergone an independent professional security audit.»

The implementation should therefore be considered experimental.

If you discover a security issue, please report it responsibly rather than exploiting it against other participants.

---

🗺️ Roadmap

The roadmap is intentionally flexible because the project is still in its early stages.

Phase 1 — Prototype

- [x] Core blockchain
- [x] Proof of Work
- [x] Fixed maximum supply
- [x] Mining rewards
- [x] Halving schedule
- [x] Transaction validation
- [x] Receiver tax
- [x] Annual wallet tax
- [x] Treasury
- [x] Multi-node prototype
- [x] Fork handling
- [x] Chain replay

Phase 2 — Hardening

- [x] Basic P2P hardening
- [x] Orphan limits
- [x] Malformed message handling
- [x] Resource limits
- [ ] Stronger P2P rate limiting
- [ ] Peer reputation/scoring
- [ ] More efficient chain synchronization
- [ ] Extensive reorganization testing
- [ ] Fuzz testing
- [ ] Signature and serialization audit
- [ ] Economic simulations

Phase 3 — Testnet

- [ ] Public testnet
- [ ] Multiple independent nodes
- [ ] Mining software
- [ ] Wallet software
- [ ] Network monitoring
- [ ] Explorer
- [ ] Testnet documentation
- [ ] Public stress testing

Phase 4 — Research & Community

- [ ] Independent security review
- [ ] Cryptoeconomic analysis
- [ ] Formal protocol documentation
- [ ] Community governance discussion
- [ ] Layer-2 research
- [ ] Performance optimization

Phase 5 — Mainnet Evaluation

A mainnet should only be considered after extensive testing and independent review.

There is currently no guarantee that Electric Money will reach mainnet.

---

🤝 Contributing

Electric Money is an open experiment.

If you are interested in contributing, there are many areas where help would be valuable:

Developers

Python, blockchain, networking, cryptography, distributed systems and performance.

Security researchers

Protocol analysis, attack simulations, fuzzing, P2P security and consensus testing.

Economists / researchers

Analysis of the monetary policy, wallet tax, Treasury mechanism and miner incentives.

Miners

Testing Proof-of-Work behavior and mining economics.

Community

Ideas, documentation, testing, feedback and discussion.

You don't need to be an expert to participate.

If you have an idea, find a bug, disagree with a design decision or simply think something could be improved, open an issue and start a discussion.

---

💬 Why I'm Building This

Electric Money started from an idea:

«What would happen if we designed a cryptocurrency around a different set of economic incentives?»

I'm still exploring that question.

I don't consider the current implementation finished, and I don't expect every design decision to be correct.

That's exactly why the project is public.

I'd like to see what other people can do with the idea, challenge it, improve it, break it, test it and potentially build something much better together.

If you find the concept interesting, feel free to join the project. ⚡

---

⚠️ Disclaimer

Electric Money is an experimental software project.

It is provided for research, development and educational purposes.

The software may contain bugs, vulnerabilities or consensus issues.

Do not use it with real funds or rely on it for financial activity.

Nothing in this repository constitutes financial, investment or legal advice.

---

📜 Protocol Parameters

Parameter| Current value
Currency| Electric Money (EM)
Consensus| Proof of Work
Target block time| 600 seconds
Initial block reward| 25 EM
Halving interval| 1,445,400 blocks
Halving period| ~27.5 years
Maximum cumulative issuance| 72,270,024.841006 EM
Receiver tax| 0.25%
Annual wallet balance tax| 0.25%
Treasury distribution| Monthly
Difficulty adjustment| Every 10 blocks
Maximum transactions/block| 5,000
Maximum block size| 2 MiB
Maximum peers| 64
Protocol version| 13

---

⚡ Join the Experiment

Electric Money is still small.

That's intentional.

There is plenty of room to influence the protocol, challenge the assumptions and shape the direction of the project.

If you are a developer, researcher, miner or simply curious about the idea, you're welcome here.

Let's build it and see where it goes. ⚡

 # MurraxCoin

MurraxCoin is purely a learning project, and as such, compromises were made to make development easier.  
The largest of these is that the official node is made in Python. This makes development much easier,
but inherits all the performance downsides of an interpreted language.

MurraxCoin is heavily inspired by [Nano](https://nano.org) and follows the same basic design principles:
- Fast
  - Uses a block-lattice design, meaning each account has its own blockchain. This means transactions can happen asynchronously.
  - Each transaction is its own block, meaning transactions do not have to wait for other transactions to fill a block.
- Feeless
  - Nodes earn no transaction fees, and instead run nodes in order to secure the network, and furthermore, their holdings.
- Environmentally friendly
  - Uses [Open Representative Voting (ORV)](https://docs.nano.org/glossary/#open-representative-voting-orv) instead of proof-of-work, which means no computational power is wasted mining.

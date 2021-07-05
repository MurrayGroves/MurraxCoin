 # MurraxCoin

[Tutorial](#Tutorial)

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


# Tutorial
- [Download](https://github.com/MurrayGroves/MurraxCoin/releases/) the latest wallet.
- Run the downloaded wallet
- Give the name of your new account (this is just for your reference)
- It will give you your MurraxCoin address!
- Go to the [faucet](https://faucet.murraygrov.es)
- Complete the captcha
- Put in your MurraxCoin address and click submit
- Check the wallet and you will now have some MurraxCoin!
- If you want to backup your private key, or access your account on another device, your keys are in `%APPDATA%/MurraxCoin/Wallet/keys/`

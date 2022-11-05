# Nimchain

This is my second project where I tried to understand blockchain technology and what makes it tick. It was very
successful, as programming a functional blockchain did make me realise the genius of this technology. This repository
is essentially my findings on the subject; the code. It is a minimally viable product, although it has no networking
functionality.

## Dependencies

The code is standard Nim, but requires `nimcrypto` and `libsodium`:

```
nimble install nimcrypto libsodium
```

## Features

What nimchain *does* have:

- Genesis block, to start the chain with
- Account/wallet creation
- Account/wallet recovery
- Transactions; sending currency to a wallet
- Transaction verification; no duplicate transactions
- Block verification; no cheating, very important

What nimchain *does not* have:

- Networking
- Census algorithm

## But where is nimchain?

**Note:** You can sign in with your GitHub account.

[https://maxwelljensen.no/git/maxwelljensen/nimchain](https://maxwelljensen.no/git/maxwelljensen/nimchain)

## Licence

This project is licensed under [European Union Public Licence
1.2](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12).

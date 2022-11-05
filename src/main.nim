import base64, colorize, libsodium/sodium, marshal, nimcrypto, os, streams, strutils, terminal, times

type
  Wallet = tuple[address: string, fullAddress: string]
  Transaction = object
    sender: Wallet
    recipient: Wallet
    signature: string
    amount: uint
  Blok = object
    timestamp: int64
    transactions: seq[Transaction]
    proof: uint
    lastBlokHash: string
  BlokCh = object
    chain: seq[Blok]
    transactions: seq[Transaction]

const Currency: tuple[name: string, ticker: string] = ("Nimcoin", "NIM")
const ProofDifficulty: int = 4
const ProofCombo: string = repeat('4', ProofDifficulty)
const SystemReward: uint = 1
const SystemWallet: Wallet = ("SYS", "SYSTEM")
const WalletLength: int = 18 # 6_402_373_705_728_000 unique combinations

# Initiate blockchain
var blokCh = BlokCh()

proc newBlok(proof: uint) =
  ## Add a new block to the blockchain
  add(blokCh.chain, Blok(
    timestamp: toUnix(getTime()),
    transactions: blokCh.transactions,
    proof: proof,
    lastBlokHash: $sha512.digest($$blokCh.chain[^1])
  ))
  blokCh.transactions = @[]

proc validateChain() =
  ## Validate the chain to make sure it is legitimate
  for blok in blokCh.chain[1..high(blokCh.chain)]:
    if ($sha512.digest($blok.proof & $blok.lastBlokHash))[^ProofDifficulty..^1] != ProofCombo:
      echo "Chain after block #", find(blokCh.chain, blok), " breaks down."
      echo "Total length of chain: ", len(blokCh.chain)
      break

proc newTransaction(sender, recipient: Wallet, privKey: string, amount: uint) =
  ## Add a new transaction to the blockchain
  add(blokCh.transactions, Transaction(
    sender: sender,
    recipient: recipient,
    signature: encode(crypto_sign(decode(privKey), $amount)),
    amount: amount
  ))

proc validateTransaction(transaction: Transaction) =
  ## Verify that a transaction was committed by the sender and nobody else
  ## A transaction is deleted if it appears more than once in the blockchain
  let signature = crypto_sign_open(decode(transaction.sender.fullAddress), decode(transaction.signature))
  if signature != $transaction.amount:
    del(blokCh.transactions, find(blokCh.transactions, transaction))
  for blokTransaction in blokCh.transactions:
    # Check that the checked transaction isn't just itself; gotta delete duplicates
    if blokTransaction != transaction and blokTransaction.signature == signature:
      del(blokCh.transactions, find(blokCh.transactions, blokTransaction))

proc validateTransactions() =
  ## Verify all transactions in the blockchain
  ## A transaction is deleted if system-awarded coins amount is more than SystemReward
  for transaction in blokCh.transactions:
    validateTransaction(transaction)
    if transaction.sender == SystemWallet and transaction.amount > SystemReward:
      del(blokCh.transactions, find(blokCh.transactions, transaction))

proc mineBlok(wallet: Wallet, privKey: string) =
  ## Mine a new block by completing intensive SHA512 calculations
  var proof: uint = 0
  let lastBlokHash = $sha512.digest($$blokCh.chain[^1])
  while proof < high(uint):
    if ($sha512.digest($proof & $lastBlokHash))[^ProofDifficulty..^1] == ProofCombo:
      echo sha512.digest($proof & $lastBlokHash)
      break
    inc(proof)
  newBlok(proof)
  newTransaction(SystemWallet, wallet, privKey, SystemReward)

proc newWallet() =
  ## Set up a new wallet
  var userWallet: Wallet
  var pubKey64: string
  var privKey64: string

  while true:
    var dupeWallet = false
    let (pubKeyBin, privKeyBin) = crypto_sign_keypair()
    pubKey64 = encode(pubKeyBin)
    privKey64 = encode(privKeyBin)
    # If the wallet is not too short and not too long then proceed to find any duplicate wallets
    # Keys are various length and have to be abbreviated to fixed length
    if len(pubKey64) >= WalletLength and len(pubKey64) <= 48:
      userWallet = (address: pubKey64[0..<WalletLength], fullAddress: pubKey64)
      for transaction in blokCh.transactions:
        if userWallet == transaction.sender or userWallet == transaction.recipient:
          dupeWallet = true
      if dupeWallet:
        for blok in blokCh.chain:
          for transaction in blok.transactions:
            if userWallet == transaction.sender or userWallet == transaction.recipient:
              dupeWallet = true
    # Exit loop if no duplicates
    if dupeWallet == false:
      break
  echo fgGreen("Success: "), "Your wallet is ", bold(userWallet.address)
  echo "Your recovery key is ", bold(privKey64), "."
  echo "Now give your wallet a name:"

  # User input for wallet name
  var name: TaintedString
  while true:
    let inputName = readLine(stdin)
    var valid = true
    for ch in inputName:
      if not isAlphaNumeric(ch):
        echo "Invalid name. Can contain only alphanumeric (a-Z..0-9) characters."
        valid = false
        break
    if valid:
      name = inputName
      break
  # Create user wallet .key file
  let walletFilePath = "wallet_" & name & ".yaml"
  if fileExists(walletFilePath):
    let existingWallet = to[Wallet]readLines(walletFilePath, 1)[0]
    echo "Looks like a wallet with name ", bold(name), " already exists: ", bold(existingWallet.address)
    echo "Closing..."
  else:
    let walletFileStream = newFileStream(walletFilePath, fmWrite)
    walletFileStream.close()
    # writeLine(walletFile, $$newWallet) # Line 1: Add deserialized wallet at
    # writeLine(walletFile, $$privKey64) # Line 2: Add private key associated with the wallet
    echo "Wallet file has been saved to ", bold(walletFilePath)

proc walletShortForm(fullAddress: string): string =
  ## Short procedure to convert full address to its short form address
  ## The full address is a public key encoded in base64
  return fullAddress[0..WalletLength+1]

proc calcWallet(wallet: Wallet) =
  ## Calculate wallet balance
  var balance: uint
  for transaction in blokCh.transactions:
    if transaction.recipient == wallet:
      balance += transaction.amount
    if transaction.sender == wallet:
      balance -= transaction.amount
  for blok in blokCh.chain:
    for transaction in blok.transactions:
      if transaction.recipient == wallet:
        balance += transaction.amount
      if transaction.sender == wallet:
        balance -= transaction.amount
  echo fgGreen("Your balance: "), balance, " ", Currency.name

proc recoverWallet(privKey64: string) =
  ## Restore wallet from private key
  let pubKey64 = encode(crypto_sign_ed25519_sk_to_pk(decode(privKey64)))
  var found = false
  # If any wallet fullAddress matching pubKey64 is found, inform user
  block search:
    for blok in blokCh.chain:
      for transaction in blok.transactions:
        if pubKey64 == transaction.sender.fullAddress or pubKey64 == transaction.recipient.fullAddress:
          found = true
          break search
  case found
  of true:
    echo fgGreen("Wallet found: "), bold(walletShortForm(pubKey64))
    calcWallet((walletShortForm(pubKey64), pubKey64))
  of false:
    echo "No wallets were found associated with that recovery code. Do you wish to restore anyway? [y/N]"
    if getch() in ['Y', 'y']:
      echo "Your wallet: ", bold(walletShortForm(pubKey64))
    else:
      echo "Closing..."

# Initiate genesis block
if len(blokCh.chain) == 0:
  add(blokCh.chain, Blok(
      timestamp: toUnix(getTime()),
      transactions: blokCh.transactions,
      proof: 1,
      lastBlokHash: "001"
    ))

newWallet()

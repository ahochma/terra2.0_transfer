from fireblocks_sdk import FireblocksSDK, TransferPeerPath, RawMessage, UnsignedMessage, VAULT_ACCOUNT, \
    TRANSACTION_STATUS_COMPLETED, TRANSACTION_STATUS_BLOCKED, TRANSACTION_STATUS_CANCELLED, TRANSACTION_STATUS_FAILED
from terra_sdk.core import Coins, AccAddress, SimplePublicKey, ModeInfo, ModeInfoSingle, SignDoc
from terra_sdk.client.lcd.api.tx import CreateTxOptions, SignerOptions
from terra_sdk.core.tx import SignMode, SignerInfo, Tx
from terra_sdk.core.auth.data import PeriodicVestingAccount
from terra_sdk.exceptions import LCDResponseError
from terra_sdk.client.lcd import LCDClient
from terra_sdk.core.bank import MsgSend
import hashlib
import time

API_KEY = "api_key"
API_SECRET = open('private.key', 'r').read()
FBKS_SDK = FireblocksSDK(API_SECRET, API_KEY)

def validate_vault(input: str) -> bool:
    try:
        if int(VAULT) in range(0, 99999999, 1):
            return 1
    except:
        return 0


def validate_dest_address(input: str) -> bool:
    res = 1
    if (len(input) != 44 or input[0:5] != "terra"):
        res = 0
    return res


VAULT = input("What is your vault account ID? ")
if not validate_vault(input):
    raise ValueError("Wrong vault account id format")
SOURCE = FBKS_SDK.get_deposit_addresses(VAULT, "LUNA")[0]["address"]
SOURCE_ACC = AccAddress(SOURCE)

DEST = input("What is your destination address?\n")
DEST_ACC = AccAddress(DEST)
if not validate_dest_address(DEST):
    raise ValueError("Wrong destination address format")

FEE_COIN = "uluna"

STATUS_KEY, MSG_KEY, SIG_KEY, FULL_SIG_KEY = "status", "signedMessages", "signature", "fullSig"
ID, SUBMIT_TIMEOUT = "id", 450  # As each transaction check occurs every 4 seconds, 450 iterations (450*4=1800 - 30 min)
COIN = "LUNA"

CHAIN = ("https://phoenix-lcd.terra.dev", "phoenix-1")
TERRA = LCDClient(CHAIN[0], CHAIN[1])


def query_coin_balance(client: LCDClient, account: AccAddress) -> int:
    """
    Query uluna amount of account
    :param client: Terra LCD Client
    :param account: AccAddress object
    :return:
    """
    coins: Coins = client.bank.balance(account)[0]
    for item in coins.to_data():
        if item['denom'] == FEE_COIN:
            return int(item['amount'])


def human_balance(total_balance: int) -> float:
    """

    :param total_balance:
    :return:
    """
    luna_balance = float(total_balance) / 1000000
    return luna_balance


def create_reg_transfer(amount: int, sender: AccAddress, recipient: AccAddress, memo: str = "") -> CreateTxOptions:
    """
    Creates a CreateTxOptions object
    :param amount:
    :param sender:
    :param recipient:
    :param memo:
    :return:
    """
    tx_options = CreateTxOptions(
        msgs=[
            MsgSend(
                sender,
                recipient,
                Coins(uluna=amount)
            )
        ],
        memo=memo,
        fee_denoms=[FEE_COIN],
        gas_adjustment=1.5
    )

    return tx_options


def create_signer_opts(source: AccAddress) -> SignerOptions:
    """
    Creates a SignerOptions object.
    :param source:
    :return:
    """
    acc_info = TERRA.auth.account_info(source)
    signer_opts = SignerOptions(
        address=source,
        sequence=acc_info.get_sequence()
    )

    return signer_opts


def convert_uluna_luna(luna: str, account_balance: int) -> int:
    """
    Converts luna to uluna. If "MAX" provides maximum transfer through account_balance.
    :param luna: Amount of Luna to transfer (or MAX)
    :param account_balance: Current balance of source account
    :return: amount of luna in uluna
    """
    if luna == "MAX":
        return account_balance

    return int(float(luna) * 1000000)


def completed_tx(fbks: FireblocksSDK, tx_id: str) -> str:
    """
    This function waits for SUBMIT_TIMEOUT seconds to retrieve status of the transaction sent to Fireblocks.
    Will stop upon completion / failure.
    :param tx_id: Transaction ID from FBKS.
    :param fbks:
    :return: Transaction last status after timeout / completion.
    """
    timeout = 0
    current_status = fbks.get_transaction_by_id(tx_id)[STATUS_KEY]
    while current_status not in (TRANSACTION_STATUS_COMPLETED, TRANSACTION_STATUS_FAILED, TRANSACTION_STATUS_BLOCKED,
                                 TRANSACTION_STATUS_CANCELLED) and timeout < SUBMIT_TIMEOUT:
        print(f"TX [{tx_id}] is currently at status - {current_status} {'.' * (timeout % 4)}                ", end="\r")
        time.sleep(4)
        current_status = fbks.get_transaction_by_id(tx_id)[STATUS_KEY]
        timeout += 1

    print(f"\nTX [{tx_id}] is currently at status - {current_status}")
    return current_status


def verify_tx(terra: LCDClient, tx_hash: str, ctr: int = 0, timeout: int = SUBMIT_TIMEOUT) -> None:
    """
    Not used at the moment. Optional to check whether the TX was actually mined.
    :param terra:
    :param tx_hash:
    :param ctr:
    :param timeout:
    :return:
    """
    if ctr == timeout:
        print(f"Timeout ({ctr} seconds) has been reached. Transaction has not been populated to block in a "
              "a timely fashion. \nConsider proposing a higher fee.")
    try:
        response = terra.tx.tx_info(tx_hash)
        if response:
            print("Transaction has completed. You may find it under the following URL:")
            print(f"https://finder.terra.money/mainnet/tx/{tx_hash}")
    except LCDResponseError:
        print(f"$ Awaiting Transaction to be mined {'.' * (ctr % 4)}    ", end="\r")
        time.sleep(1)
        verify_tx(terra, tx_hash, ctr + 1, timeout)


def retrieve_signature(fbks: FireblocksSDK, tx_id: str) -> str:
    """
    Attempts to retrieve signature, otherwise raises error.
    :param tx_id:  Transaction ID from FBKS.
    :param fbks:
    :return: Returns FBKS "fullSig", to be pushed to Stellar TransactionEnvelope.
    """
    final_status = completed_tx(fbks, tx_id)
    if final_status == TRANSACTION_STATUS_COMPLETED:
        messages = fbks.get_transaction_by_id(tx_id)
        messages = messages[MSG_KEY]
        if len(messages) > 1:
            raise ValueError(f"Found multiple messages under TX [{tx_id}]")
        else:
            return messages[0][SIG_KEY][FULL_SIG_KEY]
    else:
        if final_status == TRANSACTION_STATUS_FAILED:
            raise ValueError("Transaction resulted with status FAILED. Verify you have a valid transaction built.")
        elif final_status == TRANSACTION_STATUS_BLOCKED:
            raise NotImplementedError("Transaction Authorization Policy not implemented or Raw Signing disabled.")
        elif final_status == TRANSACTION_STATUS_CANCELLED:
            raise InterruptedError("Transaction cancelled by user.")
        else:
            raise TimeoutError("Couldn't retrieve DONE status in a timely fashion.")


def tx_with_fees(amount: int, tx_opt: CreateTxOptions, sign_opts_list: list) -> CreateTxOptions:
    """
    :param amount:
    :param tx_opt:
    :param sign_opts_list:
    :return:
    """
    estimated_fee_object = TERRA.tx.estimate_fee(sign_opts_list, tx_opt)
    estimated_fee = int(estimated_fee_object.amount.to_data()[0]['amount'])
    estimated_gas_limit = estimated_fee_object.gas_limit
    estimated_gas_price = estimated_fee / estimated_gas_limit

    total_amount = int(amount + estimated_fee)
    raw_balance = query_coin_balance(TERRA, SOURCE_ACC)

    if raw_balance == amount:
        # Fix transfer
        amount_to_transfer = int(raw_balance - estimated_fee) - 1
        tx_msg = tx_opt.msgs[0].to_data()
        tx_opt.msgs[0] = MsgSend(
            tx_msg["from_address"],
            tx_msg["to_address"],
            amount=Coins(uluna=amount_to_transfer)
        )
    elif raw_balance < total_amount:
        raise ValueError("Amount requested, with fees is higher than total account balance.")

    tx_opt.gas = int(estimated_gas_limit)
    tx_opt.gas_prices = Coins(uluna=estimated_gas_price)

    return tx_opt


def create_transaction(amount: int, fbks: FireblocksSDK, client: LCDClient, sign_opts: SignerOptions,
                       tx_opt: CreateTxOptions, vault_id: str) -> Tx:
    tx_opt = tx_with_fees(amount, tx_opt, [sign_opts])
    updated_amount = tx_opt.msgs[0].to_data()['amount'][0]['amount']
    transaction = client.tx.create([sign_opts], tx_opt)
    acc_info = client.auth.account_info(SOURCE_ACC)
    if isinstance(acc_info, PeriodicVestingAccount):
        seq = acc_info.base_vesting_account.get_sequence()
    else:
        seq = acc_info.sequence
    pub_key = fbks.get_public_key_info_for_vault_account(COIN, vault_id, "0", "0", True)
    pub_key_info = pub_key["publicKey"]
    key_bytes = bytes.fromhex(pub_key_info)
    pub_key = SimplePublicKey(
        key=key_bytes
    )
    signer_info = SignerInfo(
        public_key=pub_key,
        sequence=seq,
        mode_info=ModeInfo(
            single=ModeInfoSingle(mode=SignMode.SIGN_MODE_DIRECT)
        ),
    )
    transaction.auth_info.signer_infos.append(signer_info)

    signed_doc = SignDoc(
        chain_id=CHAIN[1],
        account_number=acc_info.get_account_number(),
        sequence=seq,
        auth_info=transaction.auth_info,
        tx_body=transaction.body
    )

    bytes_doc = signed_doc.to_bytes()
    last_attempt = hashlib.sha256(bytes_doc).hexdigest()

    unsigned_hashed_transaction = UnsignedMessage(last_attempt)
    raw_msg = RawMessage([unsigned_hashed_transaction])
    source = TransferPeerPath(VAULT_ACCOUNT, vault_id)
    transaction_note = f"Sending ~{float(updated_amount) / 1000000} Luna from Vault ID {vault_id} to {DEST}"
    raw_transaction = fbks.create_raw_transaction(raw_msg, source, COIN, note=transaction_note)
    transaction_id = raw_transaction[ID]
    final_sig = retrieve_signature(fbks, transaction_id)
    sig_bytes = bytes.fromhex(final_sig)

    transaction.signatures.append(sig_bytes)

    return transaction


if __name__ == "__main__":
    vault = VAULT
    raw_source_balance = query_coin_balance(TERRA, SOURCE_ACC)
    human_source_balance = human_balance(raw_source_balance)
    print("Your source address has:", human_source_balance, "Luna coins.")
    user_memo = input("Does the destination require a memo? Leave empty if doesn't.")
    uluna_amount = input("How much Luna would you like to transfer? (enter MAX for all Luna)\n")
    transfer_amount = convert_uluna_luna(uluna_amount, raw_source_balance)
    print(f"You're about to send:\n1. Approximately {float(transfer_amount) / 1000000} (including fees) Luna coins\n2. Destination is - "
          f"{DEST}")
    if input("This action is irreversible. Please confirm by entering YES:\n") == "YES":
        my_signer_opts = create_signer_opts(SOURCE_ACC)
        reg_tx = create_reg_transfer(transfer_amount, SOURCE_ACC, DEST_ACC, user_memo)

        tx_transaction = create_transaction(transfer_amount, FBKS_SDK, TERRA, my_signer_opts, reg_tx, vault)

        res = TERRA.tx.broadcast(tx_transaction)
        if res.txhash:
            print(f"Your TX Hash is - {res.txhash}")
            print("Transaction has completed. You may find it under the following URL:")
            print(f"https://finder.terra.money/mainnet/tx/{res.txhash}")
        else:
            print(res)
    else:
        print("Aborting action.")

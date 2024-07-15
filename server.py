from socketchildren import ServerSocketConnection
from cipher_suite import CipherSuite
from key_suite import KeySuite
from account_manager import AccountManager


SELF_HOST = "127.0.0.1"
SELF_PORT = 65414


def run_transaction(user, socket, cipher_suite):
    message_type = cipher_suite.receive_and_decode(socket)
    if message_type < 0: # did not receive
        return message_type
    elif message_type == 1: # check balance
        balance = AccountManager.get_balance(user, dollar_amount=False)
        cipher_suite.encode_and_send(balance, socket)
    elif message_type == 2: # withdraw
        amt = cipher_suite.receive_and_decode(socket)
        if amt < 0:
            return amt
        transact_val = AccountManager.withdraw_money(user, amt, dollar_amount=False)
        if transact_val:
            cipher_suite.encode_and_send(0, socket)
        else:
            cipher_suite.encode_and_send(1, socket)
    elif message_type == 3: # deposit
        amt = cipher_suite.receive_and_decode(socket)
        if amt < 0:
            return amt
        transact_val = AccountManager.deposit_money(user, amt, dollar_amount=False)
        balance = AccountManager.get_balance(user)
        if transact_val:
            cipher_suite.encode_and_send(0, socket)
        else:
            cipher_suite.encode_and_send(1, socket)
    balance = AccountManager.get_balance(user, dollar_amount=False)
    return balance




diffh_g = 18611277375118

keys = KeySuite(dh_key = 5044645123399, dh_p = 144403552893599, paillier_p = 19131612631094571991039, paillier_q = 41373129231917131175321, paillier_selfg = 9876543212, paillier_otherg = 1234567892, paillier_othern = 181051971927566029359830211681423072591853)

cipher_suite = CipherSuite(keys)


# Create shared session key section
svr = ServerSocketConnection(SELF_HOST, SELF_PORT)
session_key = cipher_suite.receive_and_decode(svr)
# To get the other side to also have the session key
cipher_suite.encode_and_send(diffh_g, svr)
# Update symmetric ciphers with session key
cipher_suite.received_session_key(session_key)
print(f"Session key: {session_key}")

# Change ciphersystems section
change_messages = []
while True:
    message = cipher_suite.receive_and_decode(svr)
    print(message)
    if message == 0:
        break
    change_messages.append(message)
for chg_msg in change_messages:
    cipher_suite.switch_ciphersystem(chg_msg)

# login section
login_successful = False
while not login_successful:
    username_int = cipher_suite.receive_and_decode(svr)
    username_str = svr.message_into_bytestring(username_int).decode("utf-8")
    password_int = cipher_suite.receive_and_decode(svr)
    password_str = svr.message_into_bytestring(password_int).decode("utf-8")
    login_successful = AccountManager.verify_login(username_str, password_str)
    if login_successful:
        print("Login succeeded")
        # 0 for success - will be the same during transactions
        cipher_suite.encode_and_send(0, svr)
    else:
        print("Login failed")
        # 1 for failure - will be the same during transactions
        cipher_suite.encode_and_send(1, svr)



# Do bank transactions
status = 0
while status >= 0:
    status = run_transaction(username_str, svr, cipher_suite)








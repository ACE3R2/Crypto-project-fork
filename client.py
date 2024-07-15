from socketchildren import ClientSocketConnection
from cipher_suite import CipherSuite
from key_suite import KeySuite
from getpass import getpass


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65414




def choose_all_cipher_systems(cipher_suite, names, socket):
    chosen_codes = [cipher_suite.cipher_system_to_code(name) for name in names]
    if len(chosen_codes) == 0 or chosen_codes[-1] != 0:
        chosen_codes.append(0)
    
    for chosen_code in chosen_codes:
        cipher_suite.encode_and_send(chosen_code, socket)
    
    # Finished signal does not change system
    for chosen_code in chosen_codes[:-1]:
        cipher_suite.switch_ciphersystem(chosen_code)
    
    

def check_balance(cipher_suite, socket):
    cipher_suite.encode_and_send(1, socket)
    return cipher_suite.receive_and_decode(socket)

def withdraw_money(amt, cipher_suite, socket):
    cipher_suite.encode_and_send(2, socket)
    cipher_suite.encode_and_send(amt, socket)
    return cipher_suite.receive_and_decode(socket)

def deposit_money(amt, cipher_suite, socket):
    cipher_suite.encode_and_send(3, socket)
    cipher_suite.encode_and_send(amt, socket)
    return cipher_suite.receive_and_decode(socket)


diffh_g = 18611277375118

keys = KeySuite(dh_key = 8413086680183, dh_p = 144403552893599, paillier_p = 4669201609102990671853, paillier_q = 38775788043632640001, paillier_selfg = 1234567892, paillier_otherg = 9876543212, paillier_othern = 791534681801253854346031374961854045149948519)

cipher_suite = CipherSuite(keys)

clt = ClientSocketConnection(SERVER_HOST, SERVER_PORT)
# To get the other side to also have the session key
cipher_suite.encode_and_send(diffh_g, clt)
session_key = cipher_suite.receive_and_decode(clt)
# Update symmetric ciphers with session key
cipher_suite.received_session_key(session_key)
print(f"Session key: {session_key}")


user_input = ""
user_choose = []
while True:
    user_input = input("Choose a cipher or MAC to switch to. Your choices are SDES, TripleSDES, Paillier, QuickMAC, or HMAC (all are case-sensitive). Press enter or type Done when you are satisfied.\n")
    if user_input == "Done" or user_input == "":
        break
    user_choose.append(user_input)
choose_all_cipher_systems(cipher_suite, user_choose, clt)


login_successful = False
while not login_successful:
    username_str = input("Choose a username: ")
    username_int = clt.bytestring_into_message(username_str.encode("utf-8"))
    password_str = getpass("Choose a password: ")
    password_int = clt.bytestring_into_message(password_str.encode("utf-8"))
    cipher_suite.encode_and_send(username_int, clt)
    cipher_suite.encode_and_send(password_int, clt)
    status = cipher_suite.receive_and_decode(clt)
    if status == 0:
        print("Login succeeded")
        login_successful = True
    else:
        print("Login failed, try again")
        
        
while True:
    user_input = input("Choose either: Check Balance, Deposit, or Withdraw, or Done if you are done transacting. Please be exact and case sensitive.\n")
    if user_input == "Done":
        break
    elif user_input == "Check Balance":
        bal = check_balance(cipher_suite, clt)
        print(f"Your balance is {bal} cents, or {bal/100} dollars")
    elif user_input == "Deposit":
        amt = input("How much would you like to deposit (in dollars)?\n")
        amt_d = int(float(amt)*100)
        status = 2
        if amt_d >= 0:
            status = deposit_money(amt_d, cipher_suite, clt)
        if status != 0:
            print("Transaction was not successful")
    elif user_input == "Withdraw":
        amt = input("How much would you like to withdraw (in dollars)?\n")
        amt_d = int(float(amt)*100)
        status = 2
        if amt_d >= 0:
            status = withdraw_money(amt_d, cipher_suite, clt)
        if status != 0:
            print("Transaction was not successful")
    else:
        print("Did not understand the request, please try again")
    
clt.close_connection()





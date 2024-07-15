from sha1 import SHA1Hasher

class AccountManager:
    # All accounts get a 100 dollar bonus upon creation
    # Alice's password is password123
    # Bob's password is letmein69
    accounts = [{'Name': 'Alice', 'Amount': 10000, 'Hash': 0x1cbad730db26426145a0b532ed9ba8ba8e11dd21},
                {'Name': 'Bob', 'Amount': 10000, 'Hash': 0x669c3357f97b36b75a07d418f7d9e5fd504df75c}]

    balance_limit = 25000000

    @classmethod
    def get_account_id(cls, account_name):
        account_id = -1
        for i, account in enumerate(cls.accounts):
            if account['Name'] == account_name:
                account_id = i
                break
        return account_id

    @classmethod
    def deposit_money(cls, account, amount, dollar_amount=True):
        if amount < 0:
            return False

        if dollar_amount:
            amount = int(amount * 100)
        else:
            amount = int(amount)

        if type(account) == str:
            account = cls.get_account_id(account)
            if account < 0:
                raise Exception('Account name is unknown')

        if cls.accounts[account]['Amount'] + amount <= cls.balance_limit:
            cls.accounts[account]['Amount'] += amount
            return True
        else:
            return False

    @classmethod
    def withdraw_money(cls, account, amount, dollar_amount=True):
        if amount < 0:
            return False

        if dollar_amount:
            amount = int(amount * 100)
        else:
            amount = int(amount)

        if type(account) == str:
            account = cls.get_account_id(account)
            if account < 0:
                raise Exception('Account name is unknown')

        if cls.accounts[account]['Amount'] - amount >= 0:
            cls.accounts[account]['Amount'] -= amount
            return True
        else:
            return False

    @classmethod
    def send_money(cls, from_accnt, to_accnt, amount, dollar_amount=True):
        if amount < 0:
            return False

        if dollar_amount:
            amount = int(amount * 100)
        else:
            amount = int(amount)

        if type(from_accnt) == str:
            from_accnt = cls.get_account_id(from_accnt)
        if type(to_accnt) == str:
            to_accnt = cls.get_account_id(to_accnt)

        if from_accnt < 0 or to_accnt < 0:
            raise Exception('Account name is unknown')

        if (cls.accounts[from_accnt]['Amount'] - amount) >= 0:
            cls.accounts[from_accnt]['Amount'] -= amount
            cls.accounts[to_accnt]['Amount'] += amount
            return True
        else:
            return False

    @classmethod
    def get_balance(cls, account, dollar_amount=True):
        if type(account) == str:
            account = cls.get_account_id(account)

        if account < 0:
            raise Exception('Account name is unknown')

        if dollar_amount:
            return cls.accounts[account]['Amount']/100
        else:
            return cls.accounts[account]['Amount']

    @classmethod
    def verify_login(cls, username, password):
        account_id = cls.get_account_id(username)
        if account_id < 0:
            return False

        sha1_hasher = SHA1Hasher()
        return cls.accounts[account_id]['Hash'] == sha1_hasher.get_hash(password)


if __name__ == "__main__":
    assert AccountManager.get_balance('Alice', False) == 10000
    assert AccountManager.get_balance('Bob', False) == 10000
    assert AccountManager.send_money('Bob', 'Alice', 20)
    assert AccountManager.get_balance('Alice', False) == 12000
    assert AccountManager.get_balance('Bob', False) == 8000
    assert AccountManager.send_money(0, 1, 60)
    assert AccountManager.get_balance('Alice') == 60.00
    assert AccountManager.get_balance('Bob') == 140.00
    assert AccountManager.send_money(0, 1, 60)
    assert AccountManager.get_balance('Alice') == 0.00
    assert AccountManager.get_balance('Bob') == 200.00
    assert not AccountManager.send_money(0, 1, 60)
    assert AccountManager.get_balance('Alice') == 0.00
    assert AccountManager.get_balance('Bob') == 200.00
    assert AccountManager.deposit_money('Alice', 20000, dollar_amount=False)
    assert AccountManager.get_balance('Alice') == 200.00
    assert AccountManager.get_balance('Bob') == 200.00
    assert AccountManager.withdraw_money('Alice', 50)
    assert AccountManager.get_balance('Alice') == 150.00
    assert AccountManager.get_balance('Bob') == 200.00
    assert not AccountManager.withdraw_money('Alice', 300)
    assert AccountManager.get_balance('Alice') == 150.00
    assert AccountManager.get_balance('Bob') == 200.00
    assert not AccountManager.deposit_money(1, 1e6)
    assert AccountManager.get_balance(0) == 150.00
    assert AccountManager.get_balance(1) == 200.00
    assert not AccountManager.deposit_money(1, -20)
    assert AccountManager.get_balance(0) == 150.00
    assert AccountManager.get_balance(1) == 200.00
    assert AccountManager.verify_login('Alice', 'password123')
    assert AccountManager.verify_login('Bob', 'letmein69')
    assert AccountManager.verify_login('Bob', 'letmein69')
    assert not AccountManager.verify_login('Bob', 'password123')
    assert not AccountManager.verify_login('Alice', 'password12')
    assert not AccountManager.verify_login('Bob', 'letmein68')
    assert not AccountManager.verify_login('Bob', '')
    print('Passed all tests')

#!/usr/bin/env python
# coding: utf-8

# In[1]:


#Import relevant libraries
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
import math



# In[2]:


class Transaction:
    def __init__(self, sender_hash, recipient_hash, sender_public_key, amount,
                fee, nonce, signature, txid):
        """
        This is the class constructor function
        """
        self.sender_hash=sender_hash
        self.recipient_hash= recipient_hash
        self.sender_public_key=sender_public_key
        self.amount=amount
        self.fee=fee
        self.nonce=nonce
        self.signature=signature
        self.txid=txid
    def verify(self, sender_balance, sender_previous_nonce):
        """
        This function verifies the transaction
        Input:
        Transaction (self)
        sender_balance (int)
        sender_previous_nonce (int)
        Returns:
        When the transaction is valid, it does not return anything.
        Raises signature error when the signature is not valid.
        Raises errors for different types of errros in the transaction.
        """
        #verify lenght of sender and recipient hash
        assert len(self.sender_hash) == 20 , "sender hash does not have the correct lenght"
        assert len(self.recipient_hash) == 20, "recipient hash does not have the correct lenght"
        
        #verify sender hash is the hash of the public key
        sha1 = hashes.Hash(hashes.SHA1())
        sha1.update(self.sender_public_key)
        sender_hash=sha1.finalize()
        assert sender_hash==self.sender_hash, "invalid sender_hash or invalid sender_public_key"
        
        #verify the amount is a whole number between 1 and  2^64 -1
        assert self.amount>0, "amount is negative" #this is verified in the function as well
        assert type(self.amount) == int, "amount is not a whole number" #this is verified in the function as well
        assert self.amount < 2**64, "amount is too high" #this is verified in the function as well
        #verify the amount is a whole number between 1 and  the amount
        assert self.fee <= self.amount, "fee is too high" #this is verified in the function as well
        assert type(self.fee)== int, "fee is not a whole number" #this is verified in the function as well
        assert self.fee >=0, "fee is negative"#this is verified in the function as well
        
        #verify there is enough balance
        assert sender_balance > (self.fee +self.amount), "there is not enough balance"
        
        #verify the nonce is equal to the previous nonce +1
        assert self.nonce ==  sender_previous_nonce +1, "invalid nonce"
        
        #specifying the hash
        chosen_hash = hashes.SHA256()
        
        #Verify txid
        hasher_txid= hashes.Hash(chosen_hash)
        hasher_txid.update(self.sender_hash)
        hasher_txid.update(self.recipient_hash)
        hasher_txid.update(self.sender_public_key)
        hasher_txid.update(self.amount.to_bytes(8, byteorder = 'little', signed = False))
        hasher_txid.update(self.fee.to_bytes(8, byteorder = 'little', signed = False))
        hasher_txid.update(self.nonce.to_bytes(8, byteorder = 'little', signed = False))
        hasher_txid.update(self.signature)
        calculated_txid=hasher_txid.finalize()
        assert calculated_txid==self.txid, 'txid incorrect'
        
        ##signature should be a valid signature
        hasher = hashes.Hash(chosen_hash)
        hasher.update(self.recipient_hash)
        hasher.update(self.amount.to_bytes(8, byteorder = 'little', signed = False))
        hasher.update(self.fee.to_bytes(8, byteorder = 'little', signed = False))
        hasher.update(self.nonce.to_bytes(8, byteorder = 'little', signed = False))
        digest_sig = hasher.finalize()
        public_key_not_encoded = serialization.load_der_public_key(self.sender_public_key)
        return public_key_not_encoded.verify(self.signature, digest_sig, ec.ECDSA(utils.Prehashed(chosen_hash)))      
        


# In[3]:


def create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce):
    """
    This function creates a new signed transaction
    Input:
    sender_private_key (instance of elliptic curve private key)
    recipient_hash (SHA-1 hash of the encoded recipient public key)
    amount (int)
    fee (int)
    nonce (int)
    Output:
    Tr (Class Transaction)
    txid (SHA-256 of the transaction)
    Signature (Signature of the transaction with sender private key)
    """
    #created sender public key encoded in DER
    sender_public_key_not_encoded = sender_private_key.public_key()
    sender_public_key=sender_public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER, 
                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    #Created sender hash
    sha1 = hashes.Hash(hashes.SHA1())
    sha1.update(sender_public_key)
    sender_hash=sha1.finalize()
    
    #Created signature
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(recipient_hash)
    if amount >= 2**64:
        raise Exception("Amount is too high")
    elif type(amount)!= int:
        raise Exception("Amount is not a whole number")
    elif amount <0:
        raise Exception("amount is negative")
    else:
        hasher.update(amount.to_bytes(8, byteorder = 'little', signed = False))
    if fee > amount:
        raise Exception("Fee is too high")
    elif type(fee)!= int:
        raise Exception("Fee is not a whole number")
    elif fee <0:
        raise Exception("fee is negative")
    else:
        hasher.update(fee.to_bytes(8, byteorder = 'little', signed = False))
    hasher.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
    digest_sig = hasher.finalize()
    signature = sender_private_key.sign( digest_sig, ec.ECDSA(utils.Prehashed(chosen_hash)))
                                        
    #created txid
    hasher_txid= hashes.Hash(chosen_hash)
    hasher_txid.update(sender_hash)
    hasher_txid.update(recipient_hash)
    hasher_txid.update(sender_public_key)
    hasher_txid.update(amount.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(fee.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(signature)
    txid=hasher_txid.finalize()
                                        
    Tr=Transaction(sender_hash=sender_hash, recipient_hash=recipient_hash, sender_public_key=sender_public_key,
                  amount=amount, fee=fee, nonce=nonce, signature=signature, txid=txid)
    return Tr, txid, signature


# # First test, this should run correctly
# * Generate a private key using ec.generate_private_key(ec.SECP256K1). 
# * Call create_signed_transaction to make a test transaction. 
# * Check that the transaction.verify call succeeds (with correct values of sender_balance and sender_previous_nonce ).
# 

# In[4]:

if __name__ == '__main__':
    #Creation of transaction
    #Created sender private key from eliptic curve
    sender_private_key=ec.generate_private_key(ec.SECP256K1)

    #Created a recipient hash either from another eliptic curve and hashing
    recipient_private_key=ec.generate_private_key(ec.SECP256K1)
    recipient_public_key_not_encoded = recipient_private_key.public_key()
    recipient_public_key=recipient_public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER, 
                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sha1 = hashes.Hash(hashes.SHA1())
    sha1.update(recipient_public_key)
    recipient_hash=sha1.finalize()

    amount= 10
    fee=2
    nonce=1000

    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # # Invalid TXID Verification
    # * Generate a valid transaction. 
    # * Check that modifying any of the fields causes transaction.
    # * Verify to raise an exception due to an invalid txid.

    # In[5]:


    #changing lengh and content of sender_hash
    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    Tr.sender_hash=bytes(1234)
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # In[6]:


    #changing sender_hash
    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    Tr.sender_hash=recipient_hash
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # In[7]:


    #changing recipient_hash
    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    Tr.recipient_hash=Tr.sender_hash
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # In[8]:


    #changing sender_public_key
    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    Tr.sender_public_key=recipient_public_key
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # In[9]:


    #changing amount
    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    Tr.amount=11
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # In[10]:


    #changing fee
    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    Tr.fee=1
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # In[11]:


    #Changing nonce
    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    Tr.nonce=1001
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # In[ ]:


    #Changing signature
    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    data = b"something different to sign"
    fake_signature = sender_private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    Tr.signature=fake_signature
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # # Invalid Signature Verification
    # * Generate a valid transaction, change the amount field, regenerate the txid so it is valid again.
    # * Check that transaction.verify raises an exception due to an invalid signature.
    # 
    # 

    # In[12]:


    Tr, txid, signature= create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce)
    #change amount
    Tr.amount=11
    #regenerate txid
    chosen_hash = hashes.SHA256()
    hasher_txid= hashes.Hash(chosen_hash)
    hasher_txid.update(Tr.sender_hash)
    hasher_txid.update(Tr.recipient_hash)
    hasher_txid.update(Tr.sender_public_key)
    hasher_txid.update(Tr.amount.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(Tr.fee.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(Tr.nonce.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(Tr.signature)
    txid=hasher_txid.finalize()
    Tr.txid=txid
    #verify signature
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # # Low balance or invalid nonce Verification
    # * Generate a valid transaction, check that transaction.verify raises an exception if either the sender_balance is too low or sender_previous_nonce is incorrect.

    # In[14]:


    #Giving low sender_balance
    Tr.verify(sender_balance=1, sender_previous_nonce=999)


    # In[ ]:


    #giving an incorrect sender_previous_nonce
    Tr.verify(sender_balance=20, sender_previous_nonce=998)


    # # Generation of new keys for invalid signature
    # * Generate two private keys, A and B. 
    # * Use A to generate a valid transaction. 
    # * Replace the signature with a signature created using B. 
    # * Regenerate the txid and confirm that transaction.verify fails with an invalid signature.

    # In[15]:


    #Creation of transaction
    #Create sender private key from eliptic curve
    private_key_A=ec.generate_private_key(ec.SECP256K1)
    private_key_B=ec.generate_private_key(ec.SECP256K1)

    #Create a recipient hash either from another eliptic curve and hashing
    recipient_private_key=ec.generate_private_key(ec.SECP256K1)
    recipient_public_key_not_encoded = recipient_private_key.public_key()
    recipient_public_key=recipient_public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER, 
                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sha1 = hashes.Hash(hashes.SHA1())
    sha1.update(recipient_public_key)
    recipient_hash=sha1.finalize()

    amount= 10
    fee=2
    nonce=1000
    #Creation of a new signature with private_key_B
    Tr, txid, signature= create_signed_transaction(private_key_A, recipient_hash, amount, fee, nonce)
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(recipient_hash)
    hasher.update(amount.to_bytes(8, byteorder = 'little', signed = False))
    hasher.update(fee.to_bytes(8, byteorder = 'little', signed = False))
    hasher.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
    digest_sig = hasher.finalize()
    signature = private_key_B.sign( digest_sig, ec.ECDSA(utils.Prehashed(chosen_hash)))
    Tr.signature=signature

    #regenerate the txid
    hasher_txid= hashes.Hash(chosen_hash)
    hasher_txid.update(Tr.sender_hash)
    hasher_txid.update(Tr.recipient_hash)
    hasher_txid.update(Tr.sender_public_key)
    hasher_txid.update(Tr.amount.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(Tr.fee.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(Tr.nonce.to_bytes(8, byteorder = 'little', signed = False))
    hasher_txid.update(Tr.signature)
    txid=hasher_txid.finalize()
    Tr.txid=txid

    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # * Check that the following transaction verifies successfully (when using sender_balance = 20 , sender_previous_nonce = 4 )
    # 

    # In[16]:


    Tr=Transaction(
    bytes.fromhex("3df8f04b3c159fdc6631c4b8b0874940344d173d"),
    bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"),
    bytes.fromhex("3056301006072a8648ce3d020106052b8104000a" +
    "03420004886ed03cb7ffd4cbd95579ea2e202f1d" +
    "b29afc3bf5d7c2c34a34701bbb0685a7b535f1e6" +
    "31373afe8d1c860a9ac47d8e2659b74d437435b0" +
    "5f2c55bf3f033ac1"),
    10,
    2,
    5,
    bytes.fromhex("3046022100f9c076a72a2341a1b8cb68520713e1" +
    "2f173378cf78cf79c7978a2337fbad141d022100" +
    "ec27704d4d604f839f99e62c02e65bf60cc93ae1"
    "735c1ccf29fd31bd3c5a40ed"),
    bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f" +
    "6c2b936e1e788c5c87657bc3"))
    Tr.verify(sender_balance=20, sender_previous_nonce=4)


    # ## Address Scheme

    # For the last part of the assignment, I need to come with an Address Scheme to check for errors in the address.
    # This is my own implementation of Luhn algorithm which is used for credit cards numbers and IDs of various countries between others.

    # In[17]:


    def Create_Check_num(recipient_hash):
        int_address=int.from_bytes(recipient_hash, "big") #converting the address to an int object
        str_address=str(int_address) #converting then to string object
        #converting it to an array of int values
        array_address=[] 
        for i in range(len(str_address)):
            array_address.append(int(str_address[i]))
        #In the second stage, I double the value of the numberst that are only in the even positions
        #In case the resulted value is double digit, I sum them again to get one digit number
        double_even_positions=[]
        for i in range(len(array_address)):
            if i%2==0:
                double=array_address[i]*2
                if math.floor(double/10)==0:
                    double_even_positions.append(double)
                else:
                    new_double=0
                    double=str(double)
                    for n in range(2):
                        new_double+=int(double[n])
                    double_even_positions.append(new_double)
            else:
                double_even_positions.append(array_address[i])
        #In the last stage we get the check_sum number by summing all the digits in the list, and get the number that needs to be added
        #to the sum to get a number that could be divided by 10. 
        check_num=10-sum(double_even_positions)%10
        return check_num        


    # In[18]:


    check_num=Create_Check_num(recipient_hash)
    check_num


    # The recipient of the money in the transaction should give his address together with a check_num number. Check_num will be an additional attribute of the transaction. 
    # Bellow I recreate the initial functions with an additional check_num variable and I verify the transaction is correct.

    # In[19]:


    class Transaction_with_check_num:
        def __init__(self, sender_hash, recipient_hash, check_num, sender_public_key, amount,
                    fee, nonce, signature, txid):
            """
            This is the class constructor function
            """
            self.sender_hash=sender_hash
            self.recipient_hash= recipient_hash
            self.sender_public_key=sender_public_key
            self.amount=amount
            self.fee=fee
            self.nonce=nonce
            self.signature=signature
            self.txid=txid
            self.check_num=check_num
        def verify(self, sender_balance, sender_previous_nonce):
            """
            This function verifies the transaction
            Input:
            Transaction (self)
            sender_balance (int)
            sender_previous_nonce (int)
            Returns:
            When the transaction is valid, it does not return anything.
            Raises signature error when the signature is not valid.
            Raises error for different types of errros in the transaction.
            """
            #verify lenght of sender and recipient hash
            assert len(self.sender_hash) == 20 , "sender hash does not have the correct lenght"
            assert len(self.recipient_hash) == 20, "recipient hash does not have the correct lenght"

            #verify sender hash is the hash of the public key
            sha1 = hashes.Hash(hashes.SHA1())
            sha1.update(self.sender_public_key)
            sender_hash=sha1.finalize()
            assert sender_hash==self.sender_hash, "invalid sender_hash or invalid sender_public_key"

            #verify the amount is a whole number between 1 and  2^64 -1
            assert self.amount>0, "amount is negative" #this is verified in the function as well
            assert type(self.amount) == int, "amount is not a whole number" #this is verified in the function as well
            assert self.amount < 2**64, "amount is too high" #this is verified in the function as well
            #verify the amount is a whole number between 1 and  the amount
            assert self.fee <= self.amount, "fee is too high" #this is verified in the function as well
            assert type(self.fee)== int, "fee is not a whole number" #this is verified in the function as well
            assert self.fee >=0, "fee is negative"#this is verified in the function as well

            #verify there is enough balance
            assert sender_balance > (self.fee +self.amount), "Balance too small"

            #verify the nonce is equal to the previous nonce +1
            assert self.nonce ==  sender_previous_nonce +1, "Invalid nonce"

            #specifying the hash
            chosen_hash = hashes.SHA256()

            #Verify txid
            hasher_txid= hashes.Hash(chosen_hash)
            hasher_txid.update(self.sender_hash)
            hasher_txid.update(self.recipient_hash)
            hasher_txid.update(self.sender_public_key)
            hasher_txid.update(self.amount.to_bytes(8, byteorder = 'little', signed = False))
            hasher_txid.update(self.fee.to_bytes(8, byteorder = 'little', signed = False))
            hasher_txid.update(self.nonce.to_bytes(8, byteorder = 'little', signed = False))
            hasher_txid.update(self.signature)
            calculated_txid=hasher_txid.finalize()
            assert calculated_txid==self.txid, 'txid incorrect'

            def Create_Check_num(recipient_hash):
                int_address=int.from_bytes(recipient_hash, "big") #converting the address to an int object
                str_address=str(int_address) #converting then to string object
                #converting it to an array of int values
                array_address=[] 
                for i in range(len(str_address)):
                    array_address.append(int(str_address[i]))
                #In the second stage, I double the value of the numberst that are only in the even positions
                #In case the resulted value is double digit, I sum them again to get one digit number
                double_even_positions=[]
                for i in range(len(array_address)):
                    if i%2==0:
                        double=array_address[i]*2
                        if math.floor(double/10)==0:
                            double_even_positions.append(double)
                        else:
                            new_double=0
                            double=str(double)
                            for n in range(2):
                                new_double+=int(double[n])
                            double_even_positions.append(new_double)
                    else:
                        double_even_positions.append(array_address[i])
                #In the last stage we get the check_sum number by summing all the digits in the list, and get the number that needs to be added
                #to the sum to get a number that could be divided by 10. 
                check_num=10-sum(double_even_positions)%10
                return check_num
            calculated_check_sum=Create_Check_num(self.recipient_hash)
            assert calculated_check_sum==self.check_num, "address not correct"


            ##signature should be a valid signature
            hasher = hashes.Hash(chosen_hash)
            hasher.update(self.recipient_hash)
            hasher.update(self.amount.to_bytes(8, byteorder = 'little', signed = False))
            hasher.update(self.fee.to_bytes(8, byteorder = 'little', signed = False))
            hasher.update(self.nonce.to_bytes(8, byteorder = 'little', signed = False))
            digest_sig = hasher.finalize()
            public_key_not_encoded = serialization.load_der_public_key(self.sender_public_key)
            return public_key_not_encoded.verify(self.signature, digest_sig, ec.ECDSA(utils.Prehashed(chosen_hash)))      



    # In[20]:


    def create_signed_transaction_with_check_num(sender_private_key, recipient_hash, check_num, amount, fee, nonce):
        """
        This function creates a new signed transaction
        Input:
        sender_private_key
        recipient_hash
        amount (int)
        fee (int)
        nonce (int)
        Output:
        Transaction
        """
        #created sender public key encoded in DER
        sender_public_key_not_encoded = sender_private_key.public_key()
        sender_public_key=sender_public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER, 
                                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)
        #Created sender hash
        sha1 = hashes.Hash(hashes.SHA1())
        sha1.update(sender_public_key)
        sender_hash=sha1.finalize()

        #Created signature
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(recipient_hash)
        if amount >= 2**64:
            raise Exception("Amount is too high")
        elif type(amount)!= int:
            raise Exception("Amount is not a whole number")
        elif amount <0:
            raise Exception("amount is negative")
        else:
            hasher.update(amount.to_bytes(8, byteorder = 'little', signed = False))
        if fee > amount:
            raise Exception("Fee is too high")
        elif type(fee)!= int:
            raise Exception("Fee is not a whole number")
        elif fee <0:
            raise Exception("fee is negative")
        else:
            hasher.update(fee.to_bytes(8, byteorder = 'little', signed = False))
        hasher.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
        digest_sig = hasher.finalize()
        signature = sender_private_key.sign( digest_sig, ec.ECDSA(utils.Prehashed(chosen_hash)))

        #created txid
        hasher_txid= hashes.Hash(chosen_hash)
        hasher_txid.update(sender_hash)
        hasher_txid.update(recipient_hash)
        hasher_txid.update(sender_public_key)
        hasher_txid.update(amount.to_bytes(8, byteorder = 'little', signed = False))
        hasher_txid.update(fee.to_bytes(8, byteorder = 'little', signed = False))
        hasher_txid.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
        hasher_txid.update(signature)
        txid=hasher_txid.finalize()

        Tr=Transaction_with_check_num(sender_hash=sender_hash, recipient_hash=recipient_hash, check_num=check_num, sender_public_key=sender_public_key,
                      amount=amount, fee=fee, nonce=nonce, signature=signature, txid=txid)
        return Tr, txid, signature


    # In[21]:


    #Creation of transaction
    #Created sender private key from eliptic curve
    sender_private_key=ec.generate_private_key(ec.SECP256K1)

    #Created a recipient hash either from another eliptic curve and hashing
    recipient_private_key=ec.generate_private_key(ec.SECP256K1)
    recipient_public_key_not_encoded = recipient_private_key.public_key()
    recipient_public_key=recipient_public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER, 
                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sha1 = hashes.Hash(hashes.SHA1())
    sha1.update(recipient_public_key)
    recipient_hash=sha1.finalize()

    amount= 10
    fee=2
    nonce=1000
    check_num=Create_Check_num(recipient_hash)

    Tr, txid, signature= create_signed_transaction_with_check_num(sender_private_key, recipient_hash, check_num, amount, fee, nonce)
    Tr.verify(sender_balance=20, sender_previous_nonce=999)


    # ### References
    # 
    # * Gocardless.com. 2021. What is the Luhn Algorithm. [online] Available at: <https://gocardless.com/guides/posts/what-is-luhn-algorithm/> [Accessed 27 June 2021].
    # * GeeksforGeeks. 2021. Luhn algorithm - GeeksforGeeks. [online] Available at: <https://www.geeksforgeeks.org/luhn-algorithm/> [Accessed 27 June 2021].

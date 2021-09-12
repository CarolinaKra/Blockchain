#!/usr/bin/env python
# coding: utf-8

# In[1]:


#Import relevant libraries
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
import math
import time
from random import randint
from random import seed
from transactions import *
import copy


# In[2]:


class UserState:
    def __init__(self, balance, nonce):
        self.balance=balance
        self.nonce=nonce


# In[3]:


class Block:
    def __init__(self, previous, height, miner, transactions, timestamp, difficulty, block_id, nonce):
        self.previous=previous
        self.height=height
        self.miner=miner
        self.transactions=transactions
        self.timestamp=timestamp
        self.difficulty=difficulty
        self.block_id=block_id
        self.nonce=nonce

    def verify_and_get_changes(self, difficulty, previous_user_states):
        
        user_states_dic=copy.deepcopy(previous_user_states)
        if self.miner not in user_states_dic:
            miner=generate_new_user(0,-1)
            user_states_dic[self.miner]=miner
        
        #the difficulty of the block should be the same as provided as argument
        #assert self.difficulty==difficulty, "difficulty doesn't match"
        
        #the lengh of the miner should be 20 bytes long
        assert len(self.miner) == 20 , "miner does not have the correct lenght"
        
        #block_id should be small enought to match difficulty of the block
        target=2**256//self.difficulty
        block_id_num=int.from_bytes(self.block_id, "big")
        assert block_id_num <= target, "block_id too large"
        
        #block_id should be correct, this should be calculated
        chosen_hash = hashes.SHA256()
        block_id_hasher = hashes.Hash(chosen_hash)
        block_id_hasher.update(self.previous)
        block_id_hasher.update(self.miner)
        for transaction in self.transactions:
            block_id_hasher.update(transaction.txid)
        block_id_hasher.update(self.timestamp.to_bytes(8, byteorder = 'little', signed = False))
        block_id_hasher.update(self.difficulty.to_bytes(16, byteorder = 'little', signed = False))
        block_id_hasher.update(self.nonce.to_bytes(8, byteorder = 'little', signed = False))
        block_id_calculated=block_id_hasher.finalize()
        assert block_id_calculated==self.block_id, "block_id incorrect"

        
        
        #Getting changes and verifying transactions
        total_fee=0
        for transaction in self.transactions:
            if transaction.recipient_hash not in user_states_dic:
                new_recipient=generate_new_user(0,-1)
                user_states_dic[transaction.recipient_hash]=new_recipient    
            transaction.verify(user_states_dic[transaction.sender_hash].balance,
                               user_states_dic[transaction.sender_hash].nonce)
            user_states_dic[transaction.sender_hash].balance=user_states_dic[transaction.sender_hash].balance-                                                                transaction.amount  
            user_states_dic[transaction.recipient_hash].balance=user_states_dic[transaction.recipient_hash].balance+                                                                transaction.amount-transaction.fee
            total_fee+=transaction.fee
            user_states_dic[transaction.sender_hash].nonce=user_states_dic[transaction.sender_hash].nonce+1
        user_states_dic[self.miner].balance=user_states_dic[self.miner].balance+total_fee+10000  
            
        return user_states_dic
    def get_changes_for_undo(self, user_states_after):
        
        user_states_dic=copy.deepcopy(user_states_after)
        
        total_fee=0
        for transaction in self.transactions:
            user_states_dic[transaction.sender_hash].balance=user_states_dic[transaction.sender_hash].balance+                                                                transaction.amount  
            user_states_dic[transaction.recipient_hash].balance=user_states_dic[transaction.recipient_hash].balance-                                                                transaction.amount+transaction.fee
            total_fee+=transaction.fee
            user_states_dic[transaction.sender_hash].nonce=user_states_dic[transaction.sender_hash].nonce-1
        user_states_dic[self.miner].balance=user_states_dic[self.miner].balance-total_fee-10000
        
        return user_states_dic


# In[1]:

def mine_block(previous, height, miner, transactions, timestamp, difficulty, cutoff_time):
    # find nonce
    chosen_hash = hashes.SHA256()
    block_id_hasher = hashes.Hash(chosen_hash)
    block_id_hasher.update(previous)
    block_id_hasher.update(miner)
    for transaction in transactions:
        block_id_hasher.update(transaction.txid)
    block_id_hasher.update(timestamp.to_bytes(8, byteorder='little', signed=False))
    block_id_hasher.update(difficulty.to_bytes(16, byteorder='little', signed=False))
    target = 2 ** 256 // difficulty
    for i in range(100000000):
        nonce_finder = block_id_hasher.copy()
        seed(i)
        nonce = randint(0, 10000000000)
        nonce_finder.update(nonce.to_bytes(8, byteorder='little', signed=False))
        nonce_finder_hash = nonce_finder.finalize()
        nonce_finder_int = int.from_bytes(nonce_finder_hash, "big")
        if nonce_finder_int <= target:
            break
        if time.time() > cutoff_time:
            return print("cutoff time over")
    block_id_hasher.update(nonce.to_bytes(8, byteorder='little', signed=False))
    block_id = block_id_hasher.finalize()

    block = Block(previous=previous, height=height, miner=miner, transactions=transactions,
                  timestamp=timestamp, difficulty=difficulty, block_id=block_id, nonce=nonce)
    return block



# In[5]:


def generate_new_user(balance, nonce):
    User=UserState(balance=balance, nonce=nonce)
    return User
    


# In[ ]:





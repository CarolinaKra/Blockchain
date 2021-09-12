#!/usr/bin/env python
# coding: utf-8

# In[2]:


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
from blocks import *
import copy


# In[3]:


class BlockchainState:
    def __init__(self, longest_chain, user_states, total_difficulty):
        self.longest_chain=longest_chain
        self.user_states=user_states
        self.total_difficulty=total_difficulty
    
    def calculate_difficulty(self):
        if len(self.longest_chain) <= 10:
            return 1000
        else:
            previous_10=self.longest_chain[-10:]
            total_difficulty_for_period=0
            for block in previous_10:
                total_difficulty_for_period+=block.difficulty
            total_time_for_period=max(self.longest_chain[-1].timestamp - self.longest_chain[-11].timestamp,1)
            return (total_difficulty_for_period // total_time_for_period *120)
    
    def verify_and_apply_block(self, block):
        #check block height is the lenght of the longest_chain
        assert block.height==len(self.longest_chain), "incorrect heigth"
        
        if self.longest_chain==[]:
            firts_block=0
            previous=firts_block.to_bytes(32, byteorder = 'little', signed = False)
            assert block.previous== previous, "previous block incorrect"
            
        else:
            assert block.previous == self.longest_chain[-1].block_id, "previous block incorrect"
            
            assert block.timestamp >= self.longest_chain[-1].timestamp, "incorrect timing"
        
        difficulty=self.calculate_difficulty()

        user_states_new=block.verify_and_get_changes(difficulty, self.user_states)
        
        self.user_states=user_states_new
        self.longest_chain.append(block)
        self.total_difficulty+=block.difficulty
    
    def undo_last_block(self):
        self.total_difficulty=self.total_difficulty - self.longest_chain[-1].difficulty
        self.user_states=self.longest_chain[-1].get_changes_for_undo(self.user_states)
        self.longest_chain=self.longest_chain[:-1]
        


# In[4]:


def verify_reorg(old_state, new_branch):
    new_state=copy.deepcopy(old_state)
    height=new_branch[0].height
    while(new_state.longest_chain[-1].height>= height):
        new_state.undo_last_block()
    for block in new_branch:
        new_state.verify_and_apply_block(block)
        
    assert new_state.total_difficulty> old_state.total_difficulty, "the new branch chain has lower difficulty"
    
    return new_state

if __name__ == '__main__':
    # In[5]:


    #I start by Creating 10 users
    #5 senders start with balance 1000
    #5 receivers start with balance 0
    #all 10 start with nonce -1
    senders_private_keys=[]
    senders_address=[]
    receivers_address=[]
    #I Create a senders and recipient hash  from another eliptic curve and hashing
    for i in range(10):
        private_key=ec.generate_private_key(ec.SECP256K1)
        public_key_not_encoded = private_key.public_key()
        public_key=public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER, 
                                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)
        sha1 = hashes.Hash(hashes.SHA1())
        sha1.update(public_key)
        address=sha1.finalize()
        if i <5:
            senders_private_keys.append(private_key)
            senders_address.append(address)
        else:
            receivers_address.append(address)       
    #I Generate user states for receivers and senders        
    senders=[]
    receivers=[]
    for i in range(10):
        if i<5:
            senders.append(generate_new_user(1000,-1))
        else:
            receivers.append(generate_new_user(0,-1))
    #I Generate the previous_user_states dictionary
    senders_address_states=dict(zip(senders_address,senders))
    receivers_address_states=dict(zip(receivers_address,receivers))
    previous_user_states = senders_address_states.copy()
    for key, value in receivers_address_states.items():
        previous_user_states[key] = value


    # In[6]:


    #initiate Blockchain
    Blockchain=BlockchainState(longest_chain=[], user_states=previous_user_states, total_difficulty=0)


    # In[ ]:


    for n in range(12):
        #I Create the transaction list, all senders sends to all receivers
        #All transactions will be done with the same amount and fee
        amount=10
        fee=1
        Transactions=[]
        for i in range(5):
            if n==0:
                nonce=0
            else:
                nonce=Blockchain.user_states[senders_address[i]].nonce + 1
            for j in range(5):
                Tr, txid, signature= create_signed_transaction(senders_private_keys[i], receivers_address[j], amount, fee, nonce)
                Transactions.append(Tr)
                nonce+=1
        #I Create a new block
        #I create a miner address 
        miner_private_key=ec.generate_private_key(ec.SECP256K1)
        miner_public_key_not_encoded = miner_private_key.public_key()
        miner_public_key=miner_public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER,
                                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        miner_sha1 = hashes.Hash(hashes.SHA1())
        miner_sha1.update(miner_public_key)
        miner_address=miner_sha1.finalize()

        difficulty=Blockchain.calculate_difficulty()
        if Blockchain.longest_chain==[]:
            firts_block=0
            previous=firts_block.to_bytes(32, byteorder = 'little', signed = False)
        else:
            previous=Blockchain.longest_chain[-1].block_id
        if n<10:
            time.sleep(120)
            #Create block
        block=mine_block(previous=previous, height=n, miner=miner_address, transactions=Transactions, timestamp=int(time.time()), 
                             difficulty=difficulty)
        Blockchain.verify_and_apply_block(block)
        print("{} block(s) mined".format(n))
            #I mine a block every 2 minutes when the difficulty is low, then, the difficulty is calculated accordingly and the next 
        #blocks should be mined every 2 minutes
        if n==8:
            user_states_at_9th_block=copy.deepcopy(Blockchain.user_states)
            total_difficulty_at_9th_block=copy.deepcopy(Blockchain.total_difficulty)


    # In[12]:


    Blockchain.longest_chain[-1].difficulty


    # In[13]:


    #Create alternative branch
    new_blockchain_alternative=BlockchainState(longest_chain=Blockchain.longest_chain[:9], user_states=user_states_at_9th_block,
                               total_difficulty=total_difficulty_at_9th_block)

    for n in range(5):
        #I Create the transaction list, all senders sends to all receivers
        #All transactions will be done with the same amount and fee
        amount=5
        fee=1
        Transactions=[]
        for i in range(5):
            nonce=new_blockchain_alternative.user_states[senders_address[i]].nonce + 1
            for j in range(5):
                Tr, txid, signature= create_signed_transaction(senders_private_keys[i], receivers_address[j], amount, fee, nonce)
                Transactions.append(Tr)
                nonce+=1
        #I Create a new block
        #I create a miner address 
        miner_private_key=ec.generate_private_key(ec.SECP256K1)
        miner_public_key_not_encoded = miner_private_key.public_key()
        miner_public_key=miner_public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER,
                                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
        miner_sha1 = hashes.Hash(hashes.SHA1())
        miner_sha1.update(miner_public_key)
        miner_address=miner_sha1.finalize()

        difficulty=new_blockchain_alternative.calculate_difficulty()
        previous=new_blockchain_alternative.longest_chain[-1].block_id
            #Create block
        if n<=1:
            time.sleep(120)
        block=mine_block(previous=previous, height=9 +n, miner=miner_address, transactions=Transactions, timestamp=int(time.time()), 
                             difficulty=difficulty)
        new_blockchain_alternative.verify_and_apply_block(block)
        print("{} block(s) mined".format(n))
        #I mine a block every 2 minutes when the difficulty is low, then, the difficulty is calculated accordingly and the next 
        #blocks should be mined every 2 minutes


    new_branch=new_blockchain_alternative.longest_chain[-5:]


    # In[14]:


    new_blockchain=verify_reorg(Blockchain, new_branch)


    # In[15]:


    len(new_blockchain.longest_chain)


    # In[16]:


    new_blockchain.total_difficulty


    # In[17]:


    new_blockchain.longest_chain[-3].difficulty


    # In[ ]:





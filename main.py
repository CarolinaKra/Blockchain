import sys
import time

import tornado

from miner import Miner
from node import Node
from connections import run_server, remote_connection
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

private_key=ec.generate_private_key(ec.SECP256K1)
public_key_not_encoded = private_key.public_key()
public_key=public_key_not_encoded.public_bytes(encoding=serialization.Encoding.DER,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
sha1 = hashes.Hash(hashes.SHA1())
sha1.update(public_key)
my_address=sha1.finalize()
print(my_address.hex())

MINER_ADDRESS = my_address


if __name__ == "__main__":
    if len(sys.argv) == 1:
        REMOTE_NODES = ["ws://ec2-18-135-206-224.eu-west-2.compute.amazonaws.com:46030/"]
        node = Node.start("./blocks.sqlite").proxy()
        miner = Miner.start(node, MINER_ADDRESS).proxy()

        for remote in REMOTE_NODES:
            remote_connection(node, remote)
        miner.start_mining()


        tornado.ioloop.IOLoop.current().start()
    elif sys.argv[1] == 'server':
        PORT = 46030
        REMOTE_NODES = []
        node = Node.start("./blocks.sqlite").proxy()
        miner = Miner.start(node, MINER_ADDRESS).proxy()
        miner.start_mining()
        run_server(node, PORT)
    else:
        print("Unknown command")
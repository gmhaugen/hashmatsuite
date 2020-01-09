import sys
import os
import random
import argparse
import getpass
import hashlib
import base64
from Crypto import Random
import time


class HashMatSuite():
    def hash(self, data, hfunc="", salt="", appendsaltlast=False):
        hashed = ""
        if hfunc.lower() == "md5":
            hashed = hashlib.md5(data.encode()).hexdigest()
        elif hfunc.lower() == "sha1":
            hashed = hashlib.sha1(data.encode()).hexdigest()
        elif hfunc.lower() == "sha256":
            hashed = hashlib.sha256(data.encode()).hexdigest()
        elif hfunc.lower() == "sha384":
            hashed = hashlib.sha384(data.encode()).hexdigest()
        elif hfunc.lower() == "sha512":
            hashed = hashlib.sha512(data.encode()).hexdigest()
        elif hfunc.lower() == "scrypt":
            if salt == "":
                print("Salt is required for scrypt")
            else:
                hashed = hashlib.scrypt()
        else:
            return ""
        
        if salt != "":
            if appendsaltlast:
                hashed = hashed + salt
            else:
                hashed = salt + hashed
        return hashed
    

    



def main(argv):
    hasher = HashMatSuite()
    print(hasher.hash("testing", hfunc="md5"))


def get_opts(args):
    parser = argparse.ArgumentParser(description="Password database")
    parser.add_argument("-i", "--inputfile", dest="inputfile", help="Input file containing entries separated by newline.", type=str)
    options = parser.parse_args(args)
    return options


if __name__ == "__main__":
    main(sys.argv[1:])

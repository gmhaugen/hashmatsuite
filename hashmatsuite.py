import sys
import os
import random
import argparse
import getpass
import hashlib
import base64
import time


class HashMatSuite():

    available_hash_functions = ["md5", "sha1", "sha256", "sha384", "sha512", "scrypt"]

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
    options = get_opts(argv)
    hasher = HashMatSuite()

    if options.listhfuncs:
        print(hasher.available_hash_functions)

    if options.text:
        if options.hashfunc:
            print(hasher.hash(options.text, hfunc=options.hashfunc))
        else:
            print("Please include which hash function to use")
        print(options.text)


def get_opts(args):
    parser = argparse.ArgumentParser(description="Arguments:")
    parser.add_argument("-i", "--inputfile", dest="inputfile", help="Input file containing entries separated by newline.", type=str)
    parser.add_argument("-t", "--text", dest="text", help="String to hash. For text with space character, enclose the text with double quotation marks.", type=str)
    parser.add_argument("-tp", "--text-secret", dest="textsecret", help="Prompts for input (input is treated as password).", action="store_true")
    parser.add_argument("-tc", "--text-clear", dest="textclear", help="Prompts for input (input is visible).", action="store_true")
    parser.add_argument("-f", "--hash-function", dest="hashfunc", help="Hash function to use.", type=str)
    parser.add_argument("-l", "--list-available-functions", dest="listhfuncs", help="Lists available hash functions", action="store_true")
    parser.add_argument("-s", "--salt", dest="salt", help="Salt to use with the given hash function.", type=str)
    parser.add_argument("-sl", "--salt-last", dest="saltlast", help="Append or prepend salt in hash.", type=bool)
    parser.add_argument("-r", "--create-rainbow-table", dest="rainbow", help="Create rainbow table of given input.", action="store_true")
    parser.add_argument("-o", "--output", dest="outputfile", help="Output file to write to.", type=str)
    options = parser.parse_args(args)
    return options


if __name__ == "__main__":
    main(sys.argv[1:])

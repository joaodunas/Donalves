import os
import random
import hmac_dbrg

##TODO mudar o metodo de pseudo random number generation para um mais seguro com seed para se poder desencriptar

class Donalves (object):
    def __init__(self, message, key):
        self.message = message 
        self.key = key ##key needs to have 256 bits/ AES also doens't work with sizes different than 128, 192, 256




    def sub_key(self, key):
        pass

    def random_number(self, bellow, key):
        dbrg = hmac_dbrg.HMAC_DRBG(key)
        bellow = hex(bellow)
        number = dbrg.generate(1)
        number = ord(number) & int(bellow, 16) ## this allows to limit the maximum value
        return number
    
    def prng_key_schedule(self, key):
        shifted_key = key[2:] + b'\x00\x00'  # Shift the key left by 2 bytes
        return shifted_key
    
    def SPN(self, number_of_rounds):
        pass

    def FN(self, number_of_rounds):
        pass


    def encrypt(self):
        #see what operation will run first
        operation = self.random_number(2, self.key)
        key = self.key
        total_rounds = 0
        while total_rounds < 13:
            key = self.prng_key_schedule(key)
            n_rounds = self.random_number(14 - total_rounds, key)
            total_rounds += n_rounds
            if operation == 0: #SPN
                operation = 1 #switch operation
                
                pass
            else: #FN
                operation = 0  #switch operation
                
                pass
            print("Total rounds: " + str(total_rounds))

        ##apply operation
        if operation == 0:
            pass
        else:
            pass




def main():
    print("Hello World!")
    key = os.urandom(64)
    print(key)
    donalves = Donalves(message="Hello World!", key=key)
    donalves.encrypt()
    

if __name__ == "__main__":
    main()

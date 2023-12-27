import random
import aeskeyschedule ##pip install aeskeyschedule

import cryptanalysis

##TODO mudar o metodo de pseudo random number generation para um mais seguro com seed para se poder desencriptar

class Donalves (object):
    def __init__(self, message, key):
        self.message = message 
        self.key = key.encode() ##key needs to have 256 bits/ AES also doens't work with sizes different than 128, 192, 256
        random.seed(key)



    def keyschedule(self):
        return aeskeyschedule.key_schedule(self.key)


    def random_number(self, bellow, op=False):
        if op:
            return random.randint(0,bellow)
        return random.randint(1, bellow)
    
    
    
    def SPN(self, number_of_rounds):
        pass

    def FN(self, number_of_rounds):
        pass


    def encrypt(self):
        #see what operation will run first
        operation = self.random_number(1, True)
        total_rounds = 0
        while total_rounds < 13:
            n_rounds = self.random_number(14 - total_rounds)
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
    key = "ArROm+4MU+Sefz3r2h8BvhVMzptfZISZ"
    donalves = Donalves(message="Hello World!", key=key)
    donalves.encrypt()
    

if __name__ == "__main__":
    main()

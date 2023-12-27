import random
import aeskeyschedule ##pip install aeskeyschedule

import cryptanalysis

##TODO mudar o metodo de pseudo random number generation para um mais seguro com seed para se poder desencriptar

class Donalves (object):
    def __init__(self, msg, key):
        self.msg = msg.encode()
        self.key = key.encode() ##key needs to have 256 bits/ AES also doens't work with sizes different than 128, 192, 256
        random.seed(key)
        self.blocks = self.slice_in_blocks()
        self.key_sched = self.keyschedule()


    def slice_in_blocks(self):
        ##slice in 16 byte blocks
        blocks = [self.msg[i:i+16] for i in range(0, len(self.msg), 16)]
        ##if last block is not 16 bytes, fill with 1s if there is 1 byte missing, 2 if there are 2 bytes missing and so on
        if len(blocks[-1]) != 16:
            missing_bytes = 16 - len(blocks[-1])
            blocks[-1] += bytes([missing_bytes] * missing_bytes)
        return blocks

    def keyschedule(self):
        return aeskeyschedule.key_schedule(self.key)


    def random_number(self, bellow, op=False):
        if op:
            return random.randint(0,bellow)
        return random.randint(2, bellow) #2 because we need at least 2 rounds for Feistel Network
    
    
    
    def SPN(self, number_of_rounds):
        pass

    def FN(self, number_of_rounds):
        for block in self.blocks:
            ##split block in 2
            left, right = block[:8], block[8:]
            ##apply Feistel Network
            for i in range(number_of_rounds):
                
                pass
            
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
                self.SPN(n_rounds)
            else: #FN
                operation = 0  #switch operation
                self.FN(n_rounds)
                
            print("Total rounds: " + str(total_rounds))

        ##apply operation
        if operation == 0:
            pass
        else:
            pass




def main():
    print("Hello World!")
    key = "ArROm+4MU+Sefz3r2h8BvhVMzptfZIxZ"
    donalves = Donalves(msg="Hello World!", key=key)
    print(donalves.key_sched)
    for i in donalves.key_sched:
        print(len(i))
    
    


    

if __name__ == "__main__":
    main()

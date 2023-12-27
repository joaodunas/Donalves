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

    def FN(self, start_round, number_of_rounds):
        j = 0
        for block in self.blocks:
            ##split block in 2
            left, right = block[:8], block[8:]
            ##apply Feistel Network
            for i in range(number_of_rounds):
                new_right = self.xor(left, right)
                left = right
                right = new_right

            ##join blocks
            block = left + right
            self.blocks[j] = block
            j += 1

    def IFN(self, number_of_rounds):
        ##inverse Feistel Network
        j = 0
        for block in self.blocks:
            ##split block in 2
            left, right = block[:8], block[8:]
            ##apply Feistel Network
            for i in range(number_of_rounds):
                new_left = self.xor(left, right)
                right = left
                left = new_left

            ##join blocks
            block = left + right
            self.blocks[j] = block
            j += 1
        
    def xor(self, a, b):
        return bytes([x ^ y for x, y in zip(a, b)])


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

        ##do last key mixing 
        for block in self.blocks:
            block = self.xor(block, self.key_sched[-1])
        




def main():
    key = "ArROm+4MU+Sefz3r2h8BvhVMzptfZIxZ"
    donalves = Donalves(msg="Hello World!", key=key)
    donalves.FN(0, 2)
    print(donalves.blocks)
    donalves.IFN(2)
    print(donalves.blocks)
    
    


    

if __name__ == "__main__":
    main()

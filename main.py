import secrets
import random
import aeskeyschedule ##pip install aeskeyschedule


class Donalves (object):
    def __init__(self, msg, key):
        self.msg = msg.encode()
        self.key = key.encode() ##key needs to have 256 bits/ AES also doens't work with sizes different than 128, 192, 256
        random.seed(key)
        self.blocks = self.slice_in_blocks()
        self.key_sched = self.keyschedule()
        
        self.sbox = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
        self.sinv = [self.sbox.index(i) for i in range(len(self.sbox))]

        self.pbox = [119, 68, 62, 33, 126, 35, 44, 75, 89, 117, 100, 6, 103, 11, 110, 21, 101, 58, 66, 48, 28, 121, 26, 82, 76, 98, 116, 63, 78, 53, 24, 60, 74, 80, 92, 115, 1, 71, 47, 41, 56, 57, 65, 81, 67, 86, 94, 111, 125, 61, 64, 49, 2, 8, 14, 127, 25, 55, 72, 39, 108, 83, 59, 69, 19, 107, 112, 118, 7, 45, 90, 50, 18, 10, 17, 22, 97, 54, 16, 38, 106, 99, 9, 37, 102, 70, 52, 4, 31, 12, 34, 93, 51, 30, 36, 32, 20, 84, 46, 91, 95, 88, 23, 87, 122, 120, 29, 5, 13, 105, 15, 73, 3, 104, 109, 79, 0, 27, 113, 77, 124, 43, 42, 40, 123, 114, 96, 85]
        self.pinv = [self.pbox.index(i) for i in range(len(self.pbox))]
                
        
    def slice_in_blocks(self):
        ##slice in 16 byte blocks
        blocks = [self.msg[i:i+16] for i in range(0, len(self.msg), 16)]
        ##if last block is not 16 bytes, fill with 1s if there is 1 byte missing, 2 if there are 2 bytes missing and so on
        if len(blocks[-1]) != 16:
            missing_bytes = 16 - len(blocks[-1])
            blocks[-1] += bytes([missing_bytes] * missing_bytes)
        return blocks


    def reconstruct_message(self):
        original_msg = b''  # Initialize an empty bytes object

        for block in self.blocks:
            original_msg += block

        # Remove padding
        last_byte = original_msg[-1]
        padding_size = last_byte if last_byte <= 16 else 0
        original_msg = original_msg[:-padding_size]

        # Decode bytes to string
        try:
            decoded_msg = original_msg.decode()
            return decoded_msg
        except UnicodeDecodeError:
            print("Error decoding message. Check the encoding.")
            return "Error decoding message. Check the encoding."
    
    
    def keyschedule(self):
        return aeskeyschedule.key_schedule(self.key)


    def random_number(self, bellow, op=False):
        if op:
            return random.randint(0,bellow)
        return random.randint(2, bellow) #2 because we need at least 2 rounds for Feistel Network
    
    
    def SPN(self, start_round, number_of_rounds):
        for i in range(len(self.blocks)):
            for j in range(number_of_rounds):

                # Start the round by mixing the subkey
                self.blocks[i] = self.xor(self.blocks[i], self.key_sched[start_round + j])
                
                # Apply the S-box
                self.blocks[i] = bytes([self.sbox[b] for b in self.blocks[i]])
                                
                block = self.blocks[i]
                # Apply the P-box
                permuted_block = bytearray(len(block))
                
                for byte_index in range(len(block)):
                    # Extract the current byte from the block
                    current_byte = block[byte_index]

                    # Apply the P-box to each bit in the byte
                    for bit_index in range(8):
                        source_bit = (current_byte >> bit_index) & 1
                        target_bit_index = self.pbox[byte_index * 8 + bit_index]
                        permuted_block[target_bit_index // 8] |= source_bit << (target_bit_index % 8)

                self.blocks[i] = bytes(permuted_block)
    
    
    def ISPN(self, start_round, number_of_rounds):
        for i in range(len(self.blocks)):            
            for j in range(number_of_rounds):
                                
                block = self.blocks[i]
                
                # Apply the inverse P-box
                inverse_permuted_block = bytearray(len(block))

                for byte_index in range(len(block)):
                    current_byte = self.blocks[i][byte_index]

                    # Apply the inverse P-box to each bit in the byte
                    for bit_index in range(8):
                        source_bit = (current_byte >> bit_index) & 1
                        target_bit_index = self.pinv[byte_index * 8 + bit_index]
                        inverse_permuted_block[target_bit_index // 8] |= source_bit << (target_bit_index % 8)

                self.blocks[i] = bytes(inverse_permuted_block)
                                
                self.blocks[i] = bytes([self.sinv[b] for b in self.blocks[i]])
                
                self.blocks[i] = self.xor(self.blocks[i], self.key_sched[start_round - j - 1])

    #similar do DES expansion function but repeating 2 bits on each side
    expansion_function = [[30, 31, 0, 1, 2, 3, 4, 5],
                          [2, 3, 4, 5, 6, 7, 8, 9],
                           [6, 7, 8, 9, 10, 11, 12, 13],
                           [10, 11, 12, 13, 14, 15, 16, 17],
                           [14, 15, 16, 17, 18, 19, 20, 21],
                           [18, 19, 20, 21, 22, 23, 24, 25],
                           [22, 23, 24, 25, 26, 27, 28, 29],
                           [26, 27, 28, 29, 30, 31, 0, 1]]     
    
    def expand_to_64(self, block): ##block comes with a size of 32 bits (4 bytes)
        #transform block from bytes to bits
        block = ''.join(format(x, '08b') for x in block)  ##08b means 8 bits for each character
        #expand block to 64 bits
        expanded_block = ''
        for i in range(len(self.expansion_function)):
            for j in range(len(self.expansion_function[i])):
                expanded_block += block[self.expansion_function[i][j]]

        return expanded_block



    def expand_to_128(self, block): ##block comes with a size of 64 bits (8 bytes)
        #divide into 2 blocks of 32 bits
        left, right = block[:4], block[4:]
        #expand each block to 64 bits
        left = self.expand_to_64(left)
        right = self.expand_to_64(right)
        #print(left+right)
        final = left + right

        return final.encode()
       
    
        
    
                    

    #just DES sbox concatenated 4 times to give a table 16x16
    des_SBOX = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6 ,12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14 ,2 ,13 ,1 ,10 ,6 ,12 ,11 ,9 ,5 ,3 ,8],
                [4, 1 ,14 ,8 ,13 ,6 ,2 ,11 ,15 ,12 ,9 ,7 ,3 ,10 ,5 ,0],
                [15 ,12 ,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11 ,3 ,14 ,10 ,0 ,6 , 13],
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6 ,12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14 ,2 ,13 ,1 ,10 ,6 ,12 ,11 ,9 ,5 ,3 ,8],
                [4, 1 ,14 ,8 ,13 ,6 ,2 ,11 ,15 ,12 ,9 ,7 ,3 ,10 ,5 ,0],
                [15 ,12 ,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11 ,3 ,14 ,10 ,0 ,6 , 13],
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6 ,12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14 ,2 ,13 ,1 ,10 ,6 ,12 ,11 ,9 ,5 ,3 ,8],
                [4, 1 ,14 ,8 ,13 ,6 ,2 ,11 ,15 ,12 ,9 ,7 ,3 ,10 ,5 ,0],
                [15 ,12 ,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11 ,3 ,14 ,10 ,0 ,6 , 13],
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6 ,12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14 ,2 ,13 ,1 ,10 ,6 ,12 ,11 ,9 ,5 ,3 ,8],
                [4, 1 ,14 ,8 ,13 ,6 ,2 ,11 ,15 ,12 ,9 ,7 ,3 ,10 ,5 ,0],
                [15 ,12 ,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11 ,3 ,14 ,10 ,0 ,6 , 13]]
    


    def back_to_64(self, block): ##block comes with a size of 128 bits (16 bytes)
        #transform block from bytes to bits
        block = ''.join(format(x, '08b') for x in block)  ##08b means 8 bits for each character
        #divide into blocks of 8 bits
        block = [block[i:i+8] for i in range(0, len(block), 8)]
        #apply sbox to each block
        #print(block)
        for i in range(len(block)):
            row = int(block[i][0] + block[i][1]+ block[i][6]+ block[i][7], 2)
            col = int(block[i][2] + block[i][3] + block[i][4] + block[i][5], 2)
            block[i] = self.des_SBOX[row][col]

        return block
        
        
    def FN(self, start_round, number_of_rounds): ##FIX esta a dar mais bytes no fim que no inicio
        i = 0
        for block in self.blocks:
            for j in range(number_of_rounds):
                ##split block in 2
                left, right = block[:8], block[8:] ##Vai ter 64 bits de cada lado e a key é de 128 bits 
                
                ## maybe expand the right block to 128 bits
                ## then XOR with key and then apply SBOX to bring the size back to 64 bits
                expanded_right = self.expand_to_128(right)
               
                expanded_right = self.xor(expanded_right, self.key_sched[start_round+j])
                #orignal_right = self.xor(expanded_right, self.key_sched[start_round+j])
                
                ##now apply SBox to bring the size back to 64 bits
                expanded_right = self.back_to_64(expanded_right)
                
                new_right = self.xor(left, expanded_right)
                left = right
                right = new_right

                ##join blocks
                block = left + right
                self.blocks[i] = block
                
            i += 1
        
        
    def IFN(self, start_round, number_of_rounds):
        ##inverse Feistel Network
        j = 0
        for block in self.blocks:
            for i in range(number_of_rounds):
                ##split block in 2
                left, right = block[:8], block[8:]
                ##apply Feistel Network
                ##expand left
                expanded_left = self.expand_to_128(left)
                ##XOR with key
                expanded_left = self.xor(expanded_left, self.key_sched[start_round-i-1])
                ##bring back to 64 bits
                expanded_left = self.back_to_64(expanded_left)

                new_left = self.xor(expanded_left, right)
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
        print("ENCRYPTING")
        while total_rounds < 13:
            n_rounds = self.random_number(14 - total_rounds)
            
            if operation == 0: #SPN
                operation = 1 #switch operation
                self.SPN(total_rounds, n_rounds)
                
            else: #FN 
                operation = 0  #switch operation
                self.FN(total_rounds, n_rounds)
                        
            total_rounds += n_rounds

        ##do last key mixing 
        for block in self.blocks:
            block = self.xor(block, self.key_sched[-1])

        ##return cypher text which is the blocks concatenated
        cypher_text = b''
        for block in self.blocks:
            cypher_text += block
        
        return cypher_text


    
    def decrypt(self, key, cypher_text=None):
        if cypher_text == None:
            pass
        else:
            self.msg = cypher_text
            self.blocks = self.slice_in_blocks()

        self.key = key.encode()
        random.seed(key)
        self.key_sched = self.keyschedule()
        
        ##do last key mixing
        for block in self.blocks:
            block = self.xor(block, self.key_sched[-1])
            
        #see what operation will run first
        operation = self.random_number(1, True)
        total_rounds = 0
        path = []
        print("DECRYPTING")
        while total_rounds < 13:
            n_rounds = self.random_number(14 - total_rounds)
            path.append([total_rounds, n_rounds])
            total_rounds += n_rounds
        
        path = path[::-1]
        reversed_path = [[14, path[0][1]]]
        
        for i in range(1, len(path)):
            reversed_path.append([path[i - 1][0], path[i][1]])
        
        
        if len(path) % 2 == 0:
            operation = not operation
        
        for i in range(len(reversed_path)):
            if operation == 0: #SPN
                operation = 1 #switch operation
                self.ISPN(reversed_path[i][0], reversed_path[i][1])
                
            else: #FN
                operation = 0
                self.IFN(reversed_path[i][0], reversed_path[i][1])


def main():
    #key = "ArROm+4MU+Sefz3r2h8BvhVMzptfZIxZ"
    key = "akjsHSDNKNJASBDUWNKJ21b325436547"
    donalves = Donalves(msg="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam sed magna arcu. Curabitur ut nunc a justo faucibus luctus. Sed tempus turpis et semper ullamcorper. In ut urna nec lorem euismod convallis. Aliquam auctor ultrices lorem, in luctus arcu viverra nec. Nullam mauris lacus, egestas ac leo nec, sollicitudin mattis ante. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Donec sit amet lobortis sapien. Mauris eget dolor mattis, posuere ligula nec, rhoncus tellus. Maecenas vitae viverra risus, et malesuada lectus. Phasellus vulputate efficitur dolor.", key=key)

    
    
    print(donalves.encrypt())
    
    print("------------------")
    print(donalves.reconstruct_message())
    print("------------------")
    donalves.decrypt(key)

    #print(donalves.blocks)
    
    print(donalves.reconstruct_message())
    
    '''

    donalves.decrypt(key, donalves.encrypt())
    print(donalves.reconstruct_message())
'''
    
    

    

if __name__ == "__main__":
    main()
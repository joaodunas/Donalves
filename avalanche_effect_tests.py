from main import Donalves
import pyaes
import pyDes
import statistics
import os

key = "akjsHSDNKNJASBDUWNKJ21b325436547"
    
original_msgs = [["abcdefghij", "klmnopqrst", "0101010101", "xyzuvwqrst", "abcdefghij", "9876543210", "abcdefg123", "abcdabcdab", "uvwxyzijkl", "1122334455"], 
                 ["abcdefghijklmnopqrst", "uvwxyz0123456789abcd", "01010101010101010101", "xyzuvwqrstijklmnopq", "abcdefghijklmnopqrst", "98765432101234567890", "abcdefghij0123456789", "abcdabcdabcdabcdabcd", "qrstuvwxyzijklmnopqrst", "11223344556677889900"], 
                 ["abcdefghijklmnopqrstuvwxyz1234", "zyxwvutsrqponmlkjihgfedcba9876", "0101010101010101010101010101010", "xyzuvwqrstijklmnopqrstuvwxyzabcd", "abcdefghijklmnopqrstuvwxyz1234", "9876543210123456789012345678901", "abcdefghij012345678901234567890121", "abcdabcdabcdabcdabcdabcdabcdabcda", "qrstuvwxyzijklmnopqrstuvwx67890123", "1122334455667788990011223344556"]]
    
    
one_diff_msgs = [['abcdefohij', 'klmno`qrst', '01010!0101', 'xyzuvwqRst', 'abcdefghib', '98765432!0', 'abcdefc123', 'abbdabcdab', 'uvwzyzijkl', '\x11122334455'],
                 ['abcdmfghijklmnopqrst', 'uvwxyz01234=6789abcd', '01010111010101010101', 'xyzuvwqrsTijklmnopq', 'abcdefghijklonopqrst', '98765632101234567890', 'abcddfghij0123456789', 'abcdabcdAbcdabcdabcd', 'qrstuvwXyzijklmnopqrst', '11223744556677889900'],
                 ['abcdefghijklmnkpqrstuvwxyz1234', 'zyxwvutsrqponmlkjihgfefcba9876', '0101010101010101210101010101010', 'xyzuvwqrstijklmnopqrst}vwxyzabcd', 'abcdefghijklmnopqrstUvwxyz1234', '9876\x1543210123456789012345678901', 'abcdefghij012345678901234%67890121', 'qbcdabcdabcdabcdabcdabcdabcdabcda', 'qrstuvwxyzijk|mnopqrstuvwx67890123', '1522334455667788990011223344556']]
    

def count_different_bits(bytes1, bytes2):
    # XOR the two sets of bytes
    xor_result = bytes([a ^ b for a, b in zip(bytes1, bytes2)])

    # Count the set bits in the XOR result
    different_bits_count = sum(bin(byte).count('1') for byte in xor_result)
    
    return different_bits_count


def test_donalves():
    
    for i in range(len(original_msgs)):
        total_count = []
        for j in range(len(original_msgs[i])):
            original_donalves = Donalves(msg=original_msgs[i][j], key=key)
            one_bit_different_donalves = Donalves(msg=one_diff_msgs[i][j], key=key)
            
            original_donalves.encrypt()
            one_bit_different_donalves.encrypt()
            
            original_blocks = original_donalves.blocks
            changed_blocks = one_bit_different_donalves.blocks
            
            count = 0
            for k in range(len(original_blocks)):
                count += count_different_bits(original_blocks[k], changed_blocks[k])
            
            print(count)

            total_count.append(count)
        
        print("Testing Length = " + str(len(original_msgs[i][0])))
        print("Average number of different bits in 10 tries: ", statistics.mean(total_count))
        print("Standard deviation: ", statistics.stdev(total_count))

    return
    

def test_aes():
    key_aes = b"akjsHSDNKNJASBDU"
    iv = "InitializationVe"
    
    for i in range(len(original_msgs)):
        total_count = []
        print("Testing Length = " + str(len(original_msgs[i][0])))
        for j in range(len(original_msgs[i])):
            aes = pyaes.AESModeOfOperationOFB(key_aes, iv=iv)
                    
            original = aes.encrypt(original_msgs[i][j])
            one_bit_different = aes.encrypt(one_diff_msgs[i][j])
            
            count = count_different_bits(original, one_bit_different)
            
            print(count)

            total_count.append(count)
            
        #print("Average number of different bits in 10 tries: ", statistics.mean(total_count))
        #print("Standard deviation: ", statistics.stdev(total_count))
    return


def test_des():
    keydes = "akjsHSDNKNJASBDU"
    for i in range(len(original_msgs)):
        total_count = []
        print("Testing Length = " + str(len(original_msgs[i][0])))
        for j in range(len(original_msgs[i])):
            
            k = pyDes.triple_des(keydes, pyDes.CBC, "\0\0\0\0\0\0\0\0",pad=None,padmode=pyDes.PAD_PKCS5)

            
            original = k.encrypt(original_msgs[i][j])
            one_bit_different = k.encrypt(one_diff_msgs[i][j])
            
            count = count_different_bits(original, one_bit_different)
            
            print(count)

            total_count.append(count)
        
        print("Average number of different bits in 10 tries: ", statistics.mean(total_count))
        print("Standard deviation: ", statistics.stdev(total_count))

    return

 
test_aes()
"""
Contains method for decoding an installation code.
"""

import binascii
import struct
import rijndael

#: Used internally by L{decode}.
crc_table = (0, 4489, 8978, 12955, 17956, 22445, 25910, 29887, 35912, 40385, 44890, 48851, 51820, 56293, 59774, 63735, 4225, 264, 13203, 8730, 22181, 18220, 30135, 25662, 40137, 36160, 49115, 44626, 56045, 52068, 63999, 59510, 8450, 12427, 528, 5017, 26406, 30383, 17460, 21949, 44362, 48323, 36440, 40913, 60270, 64231, 51324, 55797, 12675, 8202, 4753, 792, 30631, 26158, 21685, 17724, 48587, 44098, 40665, 36688, 64495, 60006, 55549, 51572, 16900, 21389, 24854, 28831, 1056, 5545, 10034, 14011, 52812, 57285, 60766, 64727, 34920, 39393, 43898, 47859, 21125, 17164, 29079, 24606, 5281, 1320, 14259, 9786, 57037, 53060, 64991, 60502, 39145, 35168, 48123, 43634, 25350, 29327, 16404, 20893, 9506, 13483, 1584, 6073, 61262, 65223, 52316, 56789, 43370, 47331, 35448, 39921, 29575, 25102, 20629, 16668, 13731, 9258, 5809, 1848, 65487, 60998, 56541, 52564, 47595, 43106, 39673, 35696, 33800, 38273, 42778, 46739, 49708, 54181, 57662, 61623, 2112, 6601, 11090, 15067, 20068, 24557, 28022, 31999, 38025, 34048, 47003, 42514, 53933, 49956, 61887, 57398, 6337, 2376, 15315, 10842, 24293, 20332, 32247, 27774, 42250, 46211, 34328, 38801, 58158, 62119, 49212, 53685, 10562, 14539, 2640, 7129, 28518, 32495, 19572, 24061, 46475, 41986, 38553, 34576, 62383, 57894, 53437, 49460, 14787, 10314, 6865, 2904, 32743, 28270, 23797, 19836, 50700, 55173, 58654, 62615, 32808, 37281, 41786, 45747, 19012, 23501, 26966, 30943, 3168, 7657, 12146, 16123, 54925, 50948, 62879, 58390, 37033, 33056, 46011, 41522, 23237, 19276, 31191, 26718, 7393, 3432, 16371, 11898, 59150, 63111, 50204, 54677, 41258, 45219, 33336, 37809, 27462, 31439, 18516, 23005, 11618, 15595, 3696, 8185, 63375, 58886, 54429, 50452, 45483, 40994, 37561, 33584, 31687, 27214, 22741, 18780, 15843, 11370, 7921, 3960)

def decode(install_string):
    """
    Converts a given installation code into a link key.  Install codes should be 48, 64, 96 or 128 bits plus an
    appended 16-bit big-endian CRC.
    
    @param install_string: The character string that is the installation code.  All non-hexadecimal characters will be 
                           removed prior to conversion.
    @type install_string: str
    @return: The big-endian binary string link key.
    @rtype: str
    """
    hex_chars = "0123456789ABCDEF"
    SECURITY_BLOCK_SIZE = 16
    
    # Extract install code and CRC from string
    # convert to upper case and remove all non-hex characters
    hex_string = ""
    for ch in install_string.upper():
        if ch in hex_chars:
            hex_string += ch
    # get length of install code (without 4 digit CRC)
    install_length = (len(hex_string) - 4) * 4
    #Spec requires that install code be 48, 64, 96 or 128 bits
    if (install_length != 48 and install_length != 64 and
       install_length != 96 and install_length != 128):
        #Spec requires that install code be one of these lengths
        raise Exception("install string not 48, 64, 96, or 128 bit")
    # convert install code and CRC to binary values
    install_code = binascii.a2b_hex(hex_string)
    given_crc = install_code[-2:]
    
    # Verify CRC
    # calculate CRC to verify install code
    crc = 0xFFFF
    for x in install_code[:-2]:
        crc = crc_table[ord(x) ^ (crc & 0xFF)] ^ (crc >> 8)
    calc_crc = struct.pack("<H", crc ^ 0xFFFF)
    if given_crc != calc_crc:
        raise Exception("CRC error on installation code given = %04X, calc = %04X" % 
                        (struct.unpack(">H", given_crc)[0], struct.unpack(">H", calc_crc)[0]))
            
    #Decode install code
    k = -(len(install_code) + 3) % SECURITY_BLOCK_SIZE
    install_code += chr(0x80) + chr(0)*k + struct.pack(">H", len(install_code)*8)
    hash = chr(0) * SECURITY_BLOCK_SIZE
    for i in range(0, len(install_code), SECURITY_BLOCK_SIZE):
        hash = e(hash, install_code[i:i + SECURITY_BLOCK_SIZE])
    return hash 

def e(hash, m):
    """
    Internal method used by L{decode}.
    """
    n = len(hash)
    aes = rijndael.rijndael(hash)
    aes_m = aes.encrypt(m)
    hash = ""
    for  i in range(0, n):
        hash += chr(ord(aes_m[i]) ^ ord(m[i]))
    return hash

if __name__ == '__main__':
    import sys
    __usage__ = 'usage: %s <code> \nconvert install code to link key'
    if len(sys.argv) != 2:
        print __usage__ % sys.argv[0]
        sys.exit(-1)
    code = decode(sys.argv[1])
    print binascii.b2a_hex(code) 

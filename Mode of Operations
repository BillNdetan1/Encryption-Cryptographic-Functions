#Note the "saes" function defined are pulled from the file titled "SAES"
#Useful functions for the code below.
#The code here was used to encrypt .bmp image files.

from sage.monoids.string_monoid import BinaryStrings
binStr = BinaryStrings()

def binaryString_from_bytes(Bytes): #Creates a binary string from the contents of a list of bytes, s
    return binStr(''.join([bin(B)[2:].rjust(8,'0') for B in Bytes]))

def bytes_from_BinaryString(s): #Converts a BinaryString s back into bytes
    return bytes((int(''.join([str(a) for a in s[i:i+8]]), 2)) for i in range(0, len(s), 8))

def xor_bool(b):
    if b:
        return 0
    return 1

def bs_xor(A,B): #XORs two binary strings A and B
    return binStr(''.join( [str(xor_bool(p[0]==p[1])) for p in zip(A,B)]))

#Example:
key = binStr("1110111011110001")
P = binStr("1100110011110111")
print(P)
C=saes(P,key,algorithm="encrypt")
print(C)
P2=saes(C,key,algorithm="decrypt")
print(P2)
      
      #Code to encrypt the file TU.bmp to TU-cbc.bmp, using the CBC mode of operation.
key=binStr("1101101100010101") #Initialize Key
IV=binStr( "1010101010101010") #Initialize IV
with open("TU.bmp","rb") as infile:  # Open Input file
    with open("TU-cbc.bmp", "wb") as outfile: #Open Outputfile
        infilecontents = infile.read()     #ReadContents of input file to list
   
        # Write header
        header = bytes(infilecontents[:0x36])  #Read in the header
        outfile.write(header)                  #Output the exact same header so that the bmp file can be viewed in the same way
      
        raw_data = bytes(infilecontents[0x36:])  #The remainder of the file is the data for each pixel of the image
        if (len(raw_data)%2>0):
            print("File length error")
            sys.exit(1)
        
        prev_CT=IV
        for i in range(0,len(raw_data)/2):  #Read through the raw_data two bytes at a time (16 bits, the blocksize of SAES)
            plaintext_block = raw_data[2*i:2*i+2] 
            plaintext_bitlist = binaryString_from_bytes(plaintext_block)  #Convert plaintext block to a BinaryString
            ciphertext_bitlist = saes(bs_xor(plaintext_bitlist,prev_CT),key,algorithm="encrypt") #Encrypt using CBC, so C_i = E(P_i xor C_{i-1})
            ciphertext_block = bytes_from_BinaryString(ciphertext_bitlist) #Convert ciphertext back to binary data to write to file
            prev_CT = ciphertext_bitlist
            outfile.write(ciphertext_block) #write ciphertext block to output file.

#(2)Code to decrypt the file CT-cbc.bmp to PT.bmp, using the CBC mode of operation.
key=binStr("1101101100010101") #Initialize Key
IV=binStr( "1010101010101010") #Initialize IV
with open("CT-cbc.bmp","rb") as infile:  # Open Input file
    with open("PT.bmp", "wb") as outfile: #Open Outputfile
        infilecontents = infile.read()     #ReadContents of input file to list
   
        # Write header
        header = bytes(infilecontents[:0x36])  #Read in the header
        outfile.write(header)                  #Output the exact same header so that the bmp file can be viewed in the same way
      
        raw_data = bytes(infilecontents[0x36:])  #The remainder of the file is the data for each pixel of the image
        if (len(raw_data)%2>0):
            print("File length error")
            sys.exit(1)
        
        prev_CT=IV
        for i in range(0,len(raw_data)/2):  #Read through the raw_data two bytes at a time (16 bits, the blocksize of SAES)
            ciphertext_block = raw_data[2*i:2*i+2] 
            ciphertext_bitlist = binaryString_from_bytes(ciphertext_block)  #Convert ciphertext block to a BinaryString
            plaintext_bitlist = saes(ciphertext_bitlist,key,algorithm="decrypt")
            plaintext_bitlist = bs_xor(plaintext_bitlist,prev_CT) #Decrypt using CBC, so P_i = D(C_i xor C_{i-1})
            plaintext_block = bytes_from_BinaryString(plaintext_bitlist) #Convert plaintext back to binary data to write to file
            prev_CT = ciphertext_bitlist
            outfile.write(plaintext_block) #write plaintext block to output file.

#(3)Code to decrypt the file TU-ecb.bmp to TU-ecb-decrypt.bmp, using the ECB mode of operation.
key=binStr("1101101100010101") #Initialize Key
IV=binStr( "1010101010101010") #Initialize IV
with open("TU-ecb.bmp","rb") as infile:  # Open Input file
    with open("TU-ecb-decypt.bmp", "wb") as outfile: #Open Outputfile
        infilecontents = infile.read()     #ReadContents of input file to list
   
        # Write header
        header = bytes(infilecontents[:0x36])  #Read in the header
        outfile.write(header)                  #Output the exact same header so that the bmp file can be viewed in the same way
      
        raw_data = bytes(infilecontents[0x36:])  #The remainder of the file is the data for each pixel of the image
        if (len(raw_data)%2>0):
            print("File length error")
            sys.exit(1)
        
        prev_CT=IV
        for i in range(0,len(raw_data)/2):  #Read through the raw_data two bytes at a time (16 bits, the blocksize of SAES)
            ciphertext_block = raw_data[2*i:2*i+2] 
            ciphertext_bitlist = binaryString_from_bytes(ciphertext_block)  #Convert ciphertext block to a BinaryString
            plaintext_bitlist = saes(ciphertext_bitlist,key,algorithm="decrypt") #decrypt using ECB, so P_i = D(C_i )
            plaintext_block = bytes_from_BinaryString(plaintext_bitlist) #Convert plaintext back to binary data to write to file
            prev_CT = ciphertext_bitlist
            outfile.write(plaintext_block) #write plaintext block to output file.

#(4)Code to encrypt the file TU.bmp to TU-ofb.bmp, using the OFB mode of operation.
key=binStr("1101101100010101") #Initialize Key
IV=binStr( "1010101010101010") #Initialize IV
with open("TU.bmp","rb") as infile:  # Open Input file
    with open("TU-ofb.bmp", "wb") as outfile: #Open Outputfile
        infilecontents = infile.read()     #ReadContents of input file to list
   
        # Write header
        header = bytes(infilecontents[:0x36])  #Read in the header
        outfile.write(header)                  #Output the exact same header so that the bmp file can be viewed in the same way
      
        raw_data = bytes(infilecontents[0x36:])  #The remainder of the file is the data for each pixel of the image
        if (len(raw_data)%2>0):
            print("File length error")
            sys.exit(1)
        
        prev_O=IV
        for i in range(0,len(raw_data)/2):  #Read through the raw_data two bytes at a time (16 bits, the blocksize of SAES)
            plaintext_block = raw_data[2*i:2*i+2] 
            plaintext_bitlist = binaryString_from_bytes(plaintext_block)  #Convert plaintext block to a BinaryString
            prev_O= saes(prev_O,key,algorithm="encrypt") #Encrypt output block using saes, so O_i = E(O_{i-1})
            ciphertext_bitlist = bs_xor(plaintext_bitlist,prev_O) #xor, so C_i = P_i xor O_i
            ciphertext_block = bytes_from_BinaryString(ciphertext_bitlist) #Convert ciphertext back to binary data to write to file
            #prev_CT = ciphertext_bitlist
            outfile.write(ciphertext_block) #write ciphertext block to output file.

#this is the script I wrote to convert the plain text of the customer data into its encrypted form.
#in actual implementation, the plain text would not exist on the system, only this encrypted version, which would be
#stored in a database. I've included the plain text in the secrets directory for reference, and so you can test run the
#software and varify that it accurately decrypts and exports the customer data. 


import Crypto
from Crypto.Cipher import DES
import hash_password

def pad(text):
    while len(text) % 8 != 0:
        text += " "
    return text

#globals

salt =''
key=''
output_path=''

input_file = open("secrets/user_plaintext.txt", 'r')
config_file = open("secrets/secrets.ini", 'r')

for line in config_file:
    data = line.split()
    if data[0] == 'salt:':
        salt = data[1]
    if data[0] == 'encryption_key:':
        key=data[1]
    if data[0] == 'data_path:':
        output_path=data[1]

des = DES.new(key, DES.MODE_ECB)    #our encryption object
                                    #we're using a des symetrical encryption for simplicity's sake
output_file = open(output_path, 'w')

for line in input_file:
    output_line = ''
    if len(line.split()) == 1 or len(line.split()) == 3 or len(line.split()) == 0:
        output_line = line
    else:
        temp = line.split()
        if temp[0] == "PIN:":
            temp[1] = hash_password.hash_password(temp[1], salt)
        else:
            temp[1] = pad(temp[1])
            temp[1] = des.encrypt(temp[1])
        output_line = temp[0] + " " + temp[1] + "\n"
    
    output_file.write(output_line)

input_file.close()
config_file.close()
output_file.close()

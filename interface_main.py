import random
import Crypto
from Crypto.Cipher import DES
import hash_password
import arrow

salt ='' 
key=''
output_path=''
data_path=''

config_file = open("secrets/secrets.ini", 'r')

for line in config_file:
    data = line.split()
    if data[0] == 'salt:':
        salt = data[1]
    if data[0] == 'encryption_key:':
        key=data[1]
    if data[0] == 'data_path:':
        data_path=data[1]
    if data[0] == 'output_path':
        output_path=data[1]

des = DES.new(key, DES.MODE_ECB)    #our encryption object, identical to the one in the encrypting script

#routines used by the system

def fetch_account(name):
#
#walks the data file and extracts the encryted data for the customer, and returns it as a dictionary
#
    record = open(data_path, 'r')
    customer = {}
    for line in record:
        if line == "Name: " + name:
            data = line.split(' ', 2)
            customer['name'] = data[1]
            customer['act#'] = record.readline().split(' ', 2)[1]
            customer['pin'] = record.readline(' ', 2).split()[1]
            customer['bal'] = record.readline(' ', 2).split()[1]    #these hashed/encrypted strings might contain spaces, so we delimit split()
    record.close()                                                  #on the first space and take the rest of the line as the cipher string
    return customer

def validate_pin(customer, pin):
#
#takes the current customer dict and the offered pin as input. Hashes the offered pin and runs a checksum against
#the pin hash on file
#
    hash_attempt = hash_password.hash_password(pin, salt)
    return (customer['pin'] == hash_attempt)

def generate_token(name):
#
#generates a session-specific token that acts as a signature and validation recipt for each
#instance of data access
#
    token = {}
    id_number = ''
    for index in range(128):
        id_number += random.choice(string.printable)
    token['id'] = id_number
    token['time'] = arrow.get().isoformat()
    token['valid'] = True
    token['customer'] = name
    return token

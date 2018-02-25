import random
import Crypto
from Crypto.Cipher import DES
import hash_password
import arrow
import string

salt ='' 
key=''
output_path=''
data_path=''
token_log = ''

config_file = open("secrets/secrets.ini", 'r')

for line in config_file:
    data = line.split()
    if data[0] == 'salt:':
        salt = data[1]
    if data[0] == 'encryption_key:':
        key=data[1]
    if data[0] == 'data_path:':
        data_path=data[1]
    if data[0] == 'output_path:':
        output_path=data[1]
    if data[0] == 'token_log:':
        token_log=data[1]

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
#generates a session-specific token that grants access to data, and doubles as a signature and validation recipt for each
#instance of data access
#
    time = arrow.get().isoformat()
    token = {}
    id_number = ''
    for index in range(16):
        id_number += random.choice(string.hexdigits)
    token['id'] = "0x"+id_number
    token['time'] = arrow.get().isoformat()
    token['valid'] = True
    token['customer'] = name
    token_record = open(token_log, "a+")
    token_record.write("Token# " + token['id'] + "\n")
    token_record.write("Issued at " + time + "\n")
    token_record.write("For customer: " + name + "\n")
    token_record.close()
    return token

def validate_token(token):
    token_record = open(token_log, "r")
    data = token_record.read()
    token_record.close()
    return (token['id'] in data and token['id'] + " invalidated" not in data and token['valid'] == True)

def invalidate_token(token):
    time = arrow.get().isoformat()
    token['valid'] = False
    token_record = open(token_log, "a+")
    token_record.write("Token " + token['id'] + " invalidated at " + time + "\n\n\n")
    token_record.close()

def get_data(customer, data_type, token):
    if not (validate_token(token)) or customer != token['customer']:
        return
    time = arrow.get().isoformat()
    customer_data = open(data_path, "r")
    line = ''
    while customer not in line:
        line = customer_data.readline()
    while data_type not in line:
        line = customer_data.readline()
    customer_data.close()
    parts = line.split()
    encoded_data = parts[1]
    output_string = "Your " + data_type + " is " + des.decrypt(encoded_data) + "\n"
    token_string = "Accessed using token " + token['id'] + " at " + time + "\n"
    customer_name = customer.split()[0] + "_" + customer.split()[1]
    output_file = open(output_path + "/" + customer_name + ".log", "a+")
    output_file.write(output_string)
    output_file.write(token_string)
    output_file.close()

token = generate_token("John Brown")
print(str(validate_token(token)))
get_data("John Brown", "Balance", token)
invalidate_token(token)
get_data("John Brown", "Balance", token)
print(str(validate_token(token)))

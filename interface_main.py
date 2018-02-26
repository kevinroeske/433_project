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
    line = ''
    while name not in line:
        try:
            line = record.readline()
        except:
            print("Profile not found")
            return {}
    if name in line:
        data = line.split(' ', 1)
        customer['Name'] = data[1]
        data = record.readline()
        customer['Acct#'] = data.split(' ', 1)[1]
        data = record.readline()
        customer['PIN'] = data.split(' ', 1)[1]                  #these hashed/encrypted strings might contain spaces, so we delimit split()
        data = record.readline()
        customer['Balance'] = data.split(' ', 1)[1]
    record.close()                                                   #on the first space and take the rest of the line as the cipher string
    return customer

def validate_pin(customer, pin):
#
#takes the current customer dict and the offered pin as input. Hashes the offered pin and runs a checksum against
#the pin hash on file
#
    hash_attempt = hash_password.hash_password(pin, salt)
    pin_hash = customer['PIN'][:len(customer['PIN'])-1]     #have to chop off the end of line character or it won't hash right
    return (pin_hash == hash_attempt)

def generate_token(name):
#
#generates a session-specific token that grants access to data, and doubles as a signature and validation recipt for each
#instance of data access
#
    time = arrow.now().isoformat()
    token = {}
    id_number = ''
    for index in range(16):
        id_number += random.choice(string.hexdigits).lower()
    token['id'] = "0x"+id_number
    token['time'] = time
    token['valid'] = True
    token['customer'] = name
    token_record = open(token_log, "a+")
    token_record.write("Token# " + token['id'] + "\n")
    token_record.write("Issued at " + time + "\n")
    token_record.write("For customer: " + name + "\n")
    token_record.close()
    return token

def validate_token(token):
    if token == {}:
        return False
    token_record = open(token_log, "r")
    data = token_record.read()
    token_record.close()
    return (token['id'] in data and token['id'] + " invalidated" not in data and token['valid'] == True)

def invalidate_token(token):
    if token == {}:
        return
    time = arrow.now().isoformat()
    token['valid'] = False
    token_record = open(token_log, "a+")
    token_record.write("Token " + token['id'] + " invalidated at " + time + "\n\n\n")
    token_record.close()

def get_data(customer, data_type, token):
    if not (validate_token(token)) or customer['Name'] != token['customer']:
        return
    time = arrow.now().isoformat()
    encoded_data = customer[data_type]
    output_string = "Your " + data_type + " is " + des.decrypt(encoded_data[:len(encoded_data)-1]) + "\n"   #again, chop off the end of
    token_string = "Token used to access " + data_type + " at " + time + "\n"                               #line character or it won't
    customer_name = customer['Name'].split()[0] + "_" + customer['Name'].split()[1]                         #decrypt
    output_file = open(output_path + "/" + customer_name + ".log", "a+")
    output_file.write(output_string)
    output_file.close()
    output_file = open(token_log, "a+")
    output_file.write(token_string)
    output_file.close()

account = fetch_account("John Brown")
token = {}
if (validate_pin(account, '7876')):
    token = generate_token(account['Name'])
print(str(validate_token(token)))
get_data(account, "Balance", token)
invalidate_token(token)
print(str(validate_token(token)))

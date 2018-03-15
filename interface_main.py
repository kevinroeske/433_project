import random
import Crypto
from Crypto.Cipher import DES
import hash_password
import arrow
import string
import os
import time

salt ='' 
key=''
output_path=''
data_path=''
token_log = ''
call_active = False

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
    if name not in record.read():
        return {}
    record.seek(0,0)
    customer = {}
    line = ''
    while name not in line:
        line = record.readline()
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
        print("Empty token")
        return False
    token_record = open(token_log, "r")
    data = token_record.read()
    token_record.close()
    return (token['id'] in data and token['id'] + " invalidated" not in data and token['valid'] == True)

def invalidate_token(token):
    if token == {} or token['valid'] == False:
        return
    time = arrow.now().isoformat()
    token['valid'] = False
    token_record = open(token_log, "a+")
    token_record.write("Token " + token['id'] + " invalidated at " + time + "\n\n\n")
    token_record.close()

def get_data(customer, data_type, token):
    if not (validate_token(token)):
        print("Invalid token")
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

def initiate_call():
    globals()['call_active']=True
    os.system('clear')
    customer_name = raw_input("Customer Name: ")
    account = fetch_account(customer_name)
    if account == {}:
        print("Account not found.")
        return
    pin_attempt = raw_input("PIN: ")
    if not validate_pin(account, pin_attempt):
        print("Invalid PIN")
        return
    token = generate_token(customer_name)
    while(globals()['call_active'] == True):
        call_menu(token, account)

def call_menu(token, account):
    os.system('clear')
    print("************************************************************************************************\n")
    print(account['Name'][:len(account['Name'])-1] + " logged in at " + token['time'] + "\n\n")
    print("************************************************************************************************\n")
    print("Main Menu\n\n")
    print("Select an option: \n")
    print("C)heck Balance\n")
    print("V)iew Account Number\n")
    print("H)ang up")
    option = raw_input("?")
    if option.lower() == 'c':
        print("Exporting Balance Information")
        get_data(account, "Balance", token)
    else:
        if option.lower() == 'v':
            print("Exporting Account Number")
            get_data(account, "Acct#", token)
        else:
            if option.lower() == 'h':
                print("Hanging up")
                invalidate_token(token)
                globals()['call_active'] = False
            else:
                print("Invalid Option")
    time.sleep(1)

input_choice = ''
while(input_choice.lower() != 'q' ):
    os.system('clear')
    print("**********************************************************************************************\n\n")
    print("Teller interface prototype 0.1\n\n")
    print("**********************************************************************************************\n\n")
    print("S)imulate customer login\n")
    print("Q)uit\n\n")
    input_choice = raw_input("?")
    if input_choice.lower() == 's':
        initiate_call()
    if input_choice.lower() != 's' and input_choice.lower() != 'q':
        print("Invalid choice")

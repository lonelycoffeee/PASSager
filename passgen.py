import random
import array

def passgen(lengthI):

    length_done = False

    lowercase_letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
                'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                'z']

    uppercase_letters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
                'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                'Z']

    digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', 
            '<', '>', '.', '/', '?', '|', '+', '-', '_', '`', 
            '~', ']', '[', '{', '}', ',']

    combine_list = lowercase_letters + uppercase_letters + digits + symbols

    rand_lower = random.choice(lowercase_letters)
    rand_upper = random.choice(uppercase_letters)
    rand_digits = random.choice(digits)
    rand_symbols = random.choice(symbols)

    temp_pass = rand_digits + rand_upper + rand_lower + rand_symbols

    while length_done != True:
        length_INP = lengthI
        try:
            length = int(length_INP)
            if length < 8:
                length = 9
                length_done = True
            elif length > 32:
                length = 9
                length_done = True
            elif length >= 8:
                length_done = True
            else:
                length = 9
                length_done = True
        except:
            length_done = True

    for x in range(length - 4):
        temp_pass = temp_pass + random.choice(combine_list)
        temp_pass_list = array.array('u', temp_pass)
        random.shuffle(temp_pass_list)

    password = ""
    for x in temp_pass_list:
        password = password + x

    return password
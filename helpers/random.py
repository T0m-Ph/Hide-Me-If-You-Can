import random
import string
from helpers import  constants

from Crypto.Random import get_random_bytes

def generateVariableName():
    return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=random.randint(constants.VARIABLE_NAME_LENGHT_MIN, constants.VARIABLE_NAME_LENGHT_MAX)))

def generateKey():
    return get_random_bytes(random.randint(constants.KEY_LENGTH_MIN, constants.KEY_LENGTH_MAX))
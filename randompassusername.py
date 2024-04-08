import random
import string


def generate_random_string(length):
    letters = string.ascii_letters
    result_str = "".join(random.choice(letters) for i in range(length))
    return result_str


# Generate a random string of length 10
print(generate_random_string(50))

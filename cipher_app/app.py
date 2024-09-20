from flask import Flask, render_template, request
import numpy as np

app = Flask(__name__)

# Vigenere Cipher
def vigenere_encrypt(plaintext, key):
    key = key.lower()
    key_length = len(key)
    cipher_text = []

    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('a')
            if char.islower():
                cipher_text.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                cipher_text.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            cipher_text.append(char)

    return ''.join(cipher_text)

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    key_length = len(key)
    plain_text = []

    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('a')
            if char.islower():
                plain_text.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
            else:
                plain_text.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
        else:
            plain_text.append(char)

    return ''.join(plain_text)

# Playfair Cipher
def generate_playfair_key_matrix(key):
    key = key.upper().replace('J', 'I')  # Replace 'J' with 'I'
    key = ''.join(sorted(set(key), key=lambda x: key.index(x)))  # Remove duplicates
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    
    matrix = []
    used_chars = set()

    # Add key characters
    for char in key:
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)

    # Add remaining alphabet characters
    for char in alphabet:
        if char not in used_chars:
            matrix.append(char)

    return [matrix[i:i+5] for i in range(0, 25, 5)]  # 5x5 matrix

def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_key_matrix(key)
    digraphs = []
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        b = plaintext[i+1] if i+1 < len(plaintext) else 'x'
        if a == b:
            digraphs.append(a + 'x')  # Add 'x' if characters are the same
            i += 1
        else:
            digraphs.append(a + b)
            i += 2

    cipher_text = []
    for digraph in digraphs:
        row1, col1 = find_position(matrix, digraph[0].upper())
        row2, col2 = find_position(matrix, digraph[1].upper())

        if row1 == row2:  # Same row
            cipher_text.append(matrix[row1][(col1 + 1) % 5].lower() if digraph[0].islower() else matrix[row1][(col1 + 1) % 5])
            cipher_text.append(matrix[row2][(col2 + 1) % 5].lower() if digraph[1].islower() else matrix[row2][(col2 + 1) % 5])
        elif col1 == col2:  # Same column
            cipher_text.append(matrix[(row1 + 1) % 5][col1].lower() if digraph[0].islower() else matrix[(row1 + 1) % 5][col1])
            cipher_text.append(matrix[(row2 + 1) % 5][col2].lower() if digraph[1].islower() else matrix[(row2 + 1) % 5][col2])
        else:  # Rectangle swap
            cipher_text.append(matrix[row1][col2].lower() if digraph[0].islower() else matrix[row1][col2])
            cipher_text.append(matrix[row2][col1].lower() if digraph[1].islower() else matrix[row2][col1])

    return ''.join(cipher_text)

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_key_matrix(key)
    plaintext = []
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i+1]
        row1, col1 = find_position(matrix, a.upper())
        row2, col2 = find_position(matrix, b.upper())

        if row1 == row2:  # Same row
            plaintext.append(matrix[row1][(col1 - 1) % 5].lower() if a.islower() else matrix[row1][(col1 - 1) % 5])
            plaintext.append(matrix[row2][(col2 - 1) % 5].lower() if b.islower() else matrix[row2][(col2 - 1) % 5])
        elif col1 == col2:  # Same column
            plaintext.append(matrix[(row1 - 1) % 5][col1].lower() if a.islower() else matrix[(row1 - 1) % 5][col1])
            plaintext.append(matrix[(row2 - 1) % 5][col2].lower() if b.islower() else matrix[(row2 - 1) % 5][col2])
        else:  # Rectangle swap
            plaintext.append(matrix[row1][col2].lower() if a.islower() else matrix[row1][col2])
            plaintext.append(matrix[row2][col1].lower() if b.islower() else matrix[row2][col1])

    return ''.join(plaintext)

# Hill Cipher
def hill_encrypt(plaintext, key_matrix):
    cipher_text = ""
    plaintext = [c.lower() if c.islower() else c.upper() for c in plaintext.replace(' ', '')]
    key_matrix = np.array(key_matrix)
    n = key_matrix.shape[0]

    if len(plaintext) % n != 0:
        plaintext += ['x' if c.islower() else 'X' for c in plaintext] * (n - len(plaintext) % n)

    for i in range(0, len(plaintext), n):
        chunk = [ord(c.upper()) - ord('A') for c in plaintext[i:i+n]]
        result = np.dot(key_matrix, chunk) % 26
        for j, r in enumerate(result):
            cipher_text += chr(r + ord('A')).lower() if plaintext[i+j].islower() else chr(r + ord('A'))

    return cipher_text

def hill_decrypt(ciphertext, key_matrix):
    plain_text = ""
    ciphertext = [c.lower() if c.islower() else c.upper() for c in ciphertext.replace(' ', '')]
    key_matrix = np.array(key_matrix)
    n = key_matrix.shape[0]

    key_inv = np.linalg.inv(key_matrix) * np.linalg.det(key_matrix)
    key_inv = np.round(key_inv).astype(int) % 26

    for i in range(0, len(ciphertext), n):
        chunk = [ord(c.upper()) - ord('A') for c in ciphertext[i:i+n]]
        result = np.dot(key_inv, chunk) % 26
        for j, r in enumerate(result):
            plain_text += chr(r + ord('A')).lower() if ciphertext[i+j].islower() else chr(r + ord('A'))

    return plain_text

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cipher_type = request.form.get('cipher_type')
        key = request.form.get('key')
        input_method = request.form.get('input_method')
        plaintext = ""

        if input_method == "text":
            plaintext = request.form.get('plaintext')
        else:
            file = request.files['file']
            plaintext = file.read().decode('utf-8')

        if len(key) < 12:
            return render_template('index.html', result="Key must be at least 12 characters long.", plaintext=plaintext)

        if cipher_type == "Vigenere":
            action = request.form.get('action')
            if action == "Encrypt":
                result = vigenere_encrypt(plaintext, key)
            else:
                result = vigenere_decrypt(plaintext, key)
        elif cipher_type == "Playfair":
            action = request.form.get('action')
            if action == "Encrypt":
                result = playfair_encrypt(plaintext, key)
            else:
                result = playfair_decrypt(plaintext, key)
        elif cipher_type == "Hill":
            action = request.form.get('action')
            key_matrix = [[int(x) for x in row.split()] for row in key.split(',')]
            if action == "Encrypt":
                result = hill_encrypt(plaintext, key_matrix)
            else:
                result = hill_decrypt(plaintext, key_matrix)

        return render_template('index.html', result=result, plaintext=plaintext)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

import random
import sympy
import tkinter as tk

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be equal.")

    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = sympy.mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    e, n = pk
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    d, n = pk
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)

def generate_keypair_and_encrypt():
    p = 61
    q = 53
    public_key, private_key = generate_keypair(p, q)
    public_key_text.delete("1.0", tk.END)
    public_key_text.insert(tk.END, str(public_key))
    private_key_text.delete("1.0", tk.END)
    private_key_text.insert(tk.END, str(private_key))

    message = input_text.get("1.0", tk.END).strip()
    cipher = encrypt(public_key, message)
    encrypted_text.delete("1.0", tk.END)
    encrypted_text.insert(tk.END, str(cipher))

def decrypt_and_display():
    private_key = eval(private_key_text.get("1.0", tk.END).strip())
    cipher = eval(encrypted_text.get("1.0", tk.END).strip())

    decrypted_message = decrypt(private_key, cipher)
    decrypted_text.delete("1.0", tk.END)
    decrypted_text.insert(tk.END, decrypted_message)

# Create the main window
window = tk.Tk()
window.title("RSA Encryption/Decryption")
window.geometry("400x500")

# Create the labels and entry fields
input_label = tk.Label(window, text="Plain Text:")
input_label.pack()

input_text = tk.Text(window, height=3, width=30)
input_text.pack()

generate_keypair_button = tk.Button(window, text="Encrypt", command=generate_keypair_and_encrypt)
generate_keypair_button.pack()

public_key_label = tk.Label(window, text="Public Key:")
public_key_label.pack()

public_key_text = tk.Text(window, height=3, width=30)
public_key_text.pack()

private_key_label = tk.Label(window, text="Private Key:")
private_key_label.pack()

private_key_text = tk.Text(window, height=3, width=30)
private_key_text.pack()

encrypted_label = tk.Label(window, text="Cipher Text:")
encrypted_label.pack()

encrypted_text = tk.Text(window, height=3, width=30)
encrypted_text.pack()

decrypted_label = tk.Label(window, text="Decrypted:")
decrypted_label.pack()

decrypted_text = tk.Text(window, height=3, width=30)
decrypted_text.pack()

# Create the buttons

decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_and_display)
decrypt_button.pack()

# Run the Tkinter event loop
window.mainloop()
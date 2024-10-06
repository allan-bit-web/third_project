import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet

# Function to generate a key and save it to a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Function to load the key from a file
def load_key():
    return open("secret.key", "rb").read()

# Function to encrypt a message
def encrypt_message(message):
    key = load_key()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

# Function to decrypt a message
def decrypt_message(encrypted_message):
    key = load_key()
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

# Function to handle encryption and display result
def encrypt():
    message = message_entry.get()
    if not message:
        messagebox.showwarning("Input Error", "Please enter a message to encrypt.")
        return
    encrypted = encrypt_message(message)
    result_entry.delete(0, tk.END)
    result_entry.insert(0, encrypted)

# Function to handle decryption and display result
def decrypt():
    encrypted_message = result_entry.get()
    if not encrypted_message:
        messagebox.showwarning("Input Error", "Please enter a message to decrypt.")
        return
    try:
        decrypted = decrypt_message(encrypted_message.encode())
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, decrypted)
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# Create the main window
root = tk.Tk()
root.title("Encrypt and Decrypt Tool")

# Create and place the widgets
tk.Label(root, text="Enter Message:").grid(row=0, column=0, padx=10, pady=10)
message_entry = tk.Entry(root, width=50)
message_entry.grid(row=0, column=1, padx=10, pady=10)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=0, column=2, padx=10, pady=10)

tk.Label(root, text="Encrypted Message:").grid(row=1, column=0, padx=10, pady=10)
result_entry = tk.Entry(root, width=50)
result_entry.grid(row=1, column=1, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=1, column=2, padx=10, pady=10)

tk.Label(root, text="Decrypted Message:").grid(row=2, column=0, padx=10, pady=10)
decrypted_entry = tk.Entry(root, width=50)
decrypted_entry.grid(row=2, column=1, padx=10, pady=10)

# Generate a key if it doesn't exist
try:
    load_key()
except FileNotFoundError:
    generate_key()

# Start the GUI event loop
root.mainloop()


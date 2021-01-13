# distributedSystem
Distributed information collection system.

# Architecture
The distributed system architecture consists of servers running continuously based on the IO Completion ports mechanism, and clients sending the necessary requests to these servers.

# Server
When creating the server program, the Windows Sockets API (WSA) was used to implement communication with the client program, and the CryptoAPI interface, to implement a secure connection.
## IO Completion ports
The server side is able to process requests from a large number of clients in parallel, thanks to the use of the IO Completion ports mechanism, the essence of which is that the caller initiates a network operation, and receives notification of its completion later.

# Client
First of all, the client must connect to the server using the connect command, after which the rest of the commands become available.
The client program is capable of providing simultaneous connection to several servers.
## Commands
* help - show Help list
* connect <ip> <port> - connect to the server
* exit - exit the program
* ct <serv_num> - request current time from the server
* st <serv_num> - request time since OS startup from the server
* os <serv_num> - request OS info from the server
* ms <serv_num> - request memory status from the server
* di <serv_num> - request drives info from the server
* ar <path> <serv_num> - request file access rights from the server
* ow <path> <serv_num> - request file owner from the server

# Interaction
All messages between the client and the server are encrypted. Encryption is provided using the CryptoAPI.
When the client connects to the server, a key pair (public and private) is generated. The public key is sent to the server, which uses it to encrypt the generated session key. It is sent to the client, who decrypts it using the private key. In the future, it is the session key that is used to encrypt messages.

# Output
The response format is structured similarly to .json files, which not only provides a user-friendly experience, but also machine-readability
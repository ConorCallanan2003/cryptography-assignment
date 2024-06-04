# Secure File Transfer Application - The Real Glynn Shady
LM173- CS4455 - Cybersecurity & Cryptography <br>
Conor Callanan, Conor Glynn, Karl Gilmartin

## Summary

This project implements a secure, end-to-end encrypted file-sharing application. The application ensures that all communications between users are secure, authenticated, and verifiable to protect against unauthorized access and tampering.



## Features

- **User Registration and Authentication**: Secure user registration and login system using secure passwords and JWTs.
- **End-to-End Encryption**: Client-side encryption and decryption to ensure files are only readable by intended recipients. Files are end-to-end encrypted.
- **File Upload and Download**: Authenticated users can upload files securly and only the intended recipient can download the file.
- **Digital Signatures**: Ensure integrity and authenticity of the files and shared keys.
- **"Revokable" JWTs**: Due to our use of a blocklist for JWTs that we no longer want to accept. We can implement features like login attempt limits and replay attack protection.
- **Limited login attempts**: Use of JWT to limit the number of times a user can try to log in and to maintain the users session.
- **Replay attack protection**: When a user submits a request to a replay attack protected endpoint, they are issued a new JWT and their old one is added to the blocklist.
- **Captcha Challenge**: Users must complete a Captcha challenge before attempting to log in. 
- **Secure password hashing**: User passwords are never stored in plaintext.

## Overview

### User Registration and Authentication
- Users can create an account with a username and password. A private/public key pair is also generated for them. They can choose where to store this data.
- For each subsequent login, the user must provide their username and password and the path to their user data (which includes their private key).
- The server stores the user's password securely using a salted hash.
- JWT tokens are used to limimt the numebr of times a user can try to logged in. On each failed attempt, their previous token is added to the blocklist and they are issues with a new one with an updated count of their number of attempts.
- Once they login successfully, they are provided with a JWT containing their userid that can be used to authenticate requests for the remaining duration of their session.
- If the user reaches the maximum number of login attempts, the user must complete the captcha again to login.

### End-to-End Encryption
- Shared key is generated using a secure PRNG and encrypted using the recipient's public key.
- A shared key is generated for each file and shared with the intended recipient.
- Files are encrypted on the client-side before being uploaded to the server using AES (CTR mode).
- Both the ciphertext and the encrypted secret are signed using the sender's private key before being sent.
- The server stores the encrypted file, sender, receiptent, encrypted shared key and signatures.
- Files are verified and then decrypted on the client-side after being downloaded from the server.
- Receivers must first decrypt the symmetric key using their private key before decrypting the file with said key.

### Digital Signatures
- Files and shared keys are signed using the sender's private key to ensure integrity and authenticity.
- Receivers can verify both signatures using the sender's public key.

### Database Security
- User passwords are stored securely using a salted hash.
- Regex and sanaity checks are used to ensure that the data is valid.

### Captcha Verification
- To get a token that can be used to attempt to login, users must first complete a captcha. 
- The captcha uses logic-based captcha questions retrieved from textcaptcha.com's API and encodes them as a random ASCII art font using the Python `art` library. As a result, most questions cannot be parsed by LLMs and require a human to read and answer. 
- This, combined with the limit on login attempts, makes brute forcing login details extremely difficult. 

### Preventing Side-Channel Attacks/Leaking Data on Login Request
- All responses to the login endpoint are slowed to 0.5 seconds in an attempt to protect against side-channel attacks and data leaking.

### Use ORM to Prevent Risk of SQL Injection
- Used the Peewee ORM for Python to interact with our SQLite database.
- Ensured not to use any raw SQL but rather use Peewee models for database interactions.
- This eliminates the risk of user-entered data being executed on the database. 

## Tech Stack
- **Backend**: Python (FastAPI)
- **Database**: SQLite
- **Encryption**: RSA, AES (CTR mode)

## Installation

### Setup

To use you must have Python 3.12 installed.

1. **Clone the repository**:
   ```sh
   git clone https://github.com/ConorCallanan2003/cryptography-assignment
    ```

2. **Create virtual env and install dependencies - Client**:
    ```sh
    cd cryptography-assignment/client
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
   ```
3. **Create virtual env and install dependencies - Server**:
    ```sh
    cd cryptography-assignment/server
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
5. **Run the server**
    ```sh
    python -m uvicorn server:app
    ```
6. **Run the client**
    ```sh
    cd cryptography-assignment/client
    python client.py
    ```
## Planning
Here are some photos from our planning meetings, with different versions of our project.

**Version 1:** <br>

![image](./assets/photos/Version1Photo2.jpg)

Using only Assemectric encryption with the public and private keys of sender and receiver for both encryption and signatures. Limitations: slow, size limit. <br>

**Version 2 :**<br>

![image](./assets/photos/Version1Photo1.jpg)

Generating a shared private key for semmectric encryption. Using RSA for sending the shared key and AES for the file encryption. Using digital signatures. Limitations: lack of enchanced safety features such as password, jwts 
<br>



**Version 3 (Final Version):**<br>

![image](./assets/photos/Version2Photo1.jpg)
<br>
Improvements: Added user login and registration, JWTs, captcha, jwt block list. <br>

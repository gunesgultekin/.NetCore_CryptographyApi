##  .NET Core Data Signing & Encryption Backend Web API
This project was developed with the aim of implementing file encryption, decryption, digital signature generation, and verification processes within the context of the "Public Key Infrastructure" and "Cryptographic Algorithms" topics covered in the cybersecurity course.

# To Run:
* Change "connectionString" within the /Context/connectionConfiguration.cs with your own MSSQL database connection string
* Connection string format:
* "Data Source= (your pc name ) \\SQLEXPRESS; Initial Catalog = (your database name); Integrated Security = True; TrustServerCertificate=True"
  
* Since Entity Framework ORM has used in this project, you must initialize two database tables named as "Messages" and "Users".
* Messages table consists of the attributes "id", "messageBody" and "digitalSignature"
* Users table consists of the attributes "id", "username" "publicKey", "privateKey", "aesKey" and "aesIV"

* symmetricEncryption method is designed to accept a file path as input and proceed to encrypt the file through a symmetric AES encryption process, utilizing a securely generated AES key.
  
* symmetricDecryption method operates by receiving a file path and decrypting the file using the symmetric AES key provided by the sender

* createDigitalSignature function operates by accepting a filepath as input, initiating by computing the SHA-512 value of the file. Subsequently, it encrypts the resulting hash through an asymmetric RSA algorithm, utilizing the sender's private key.
  
* verifyDigitalSignature function begins by decrypting the file using an asymmetric RSA algorithm and the sender's public key. It then compares the decrypted value with the hash value of the received file. Successful verification is determined if the hashed value matches the decrypted value.

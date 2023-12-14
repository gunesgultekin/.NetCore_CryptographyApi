##  .NET Core Data Signing & Encryption Backend Web API
# To Run:
* Change "connectionString" within the /Context/connectionConfiguration.cs with your own MSSQL database connection string
* Connection string format: "Data Source= (your pc name ) \\SQLEXPRESS; Initial Catalog = (your database name); Integrated Security = True; TrustServerCertificate=True"
* Since Entity Framework ORM has used in this project, you must initialize two database tables named as "Messages" and "Users".
* Messages table consists of the attributes "id", "messageBody" and "digitalSignature"
* Users table consists of the attributes "id", "username" "publicKey", "privateKey", "aesKey" and "aesIV"

* symmetricEncryption function takes a filepath then encrpyt this file using symmetric aes encryption with securely generated aes key.
  
* symmetricDecryption function takes a filepath then decrypt this file using the symmetric aes key received from the sender

* createDigitalSignature function takes a filepath then first calculates the SHA-512 value of the file then encrypts the hashed file with asymmetric RSA algorithm using sender's private key

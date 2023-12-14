using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using PUBLIC_KEY_INFRASTRUCTURE.Context;
using PUBLIC_KEY_INFRASTRUCTURE.Entities;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace PUBLIC_KEY_INFRASTRUCTURE.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private DBContext _context;

        public UsersController(DBContext context)
        {
            this._context = context;
            
          
        }

        // ENCRYPT DESIRED FILE WITH SYMMETRIC AES ENCRYPTION
        [HttpGet("symmetricEncryption")]
        public void symmetricEncrypion(string filePath)
        {

            var checkDuplicate = _context.Messages.FirstOrDefault(m => m.messageBody == filePath); // CHECK IS GIVEN FILE PATH DUPLICATED

            if (checkDuplicate == null) // IF FILE PATH IS UNIQUE
            {
                // GENERATE A NEW OUTPUT PATH FOR THE FILE TO BE ENCRYPTED 
                // ENCRYPTED FILE WILL BE SAVED TO YOUR DESKTOP AS "EncryptedFile"
                string outputFilePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "EncryptedFile" + Path.GetExtension(filePath));
                

                // AES ENCRYPTION PROCESS
                using (FileStream fsInput = new FileStream(filePath, FileMode.Open)) // OPEN THE FILE AT THE GIVEN ADDRESS
                {
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create)) // CREATE A NEW OUTPUT FILE as "EncrypedFile"
                    {
                        using (AesManaged aes = new AesManaged())
                        {
                            aes.GenerateKey(); // GENERATE SYMMETRIC AES KEY
                            aes.GenerateIV(); 

                            var sender = _context.Users.FirstOrDefault(u => u.username == "A"); // GET USER A (SENDER) FROM DATABASE
                            sender.aesKey = aes.Key; // SAVE SENDER'S SYMMETRIC AES KEY 
                            sender.aesIV = aes.IV;
                            _context.Entry(sender).State = EntityState.Modified; 
                            _context.SaveChanges(); // SAVE CHANGED INFO TO DATABASE

                            // PERFORM ENCRYPTION
                            ICryptoTransform encryptor = aes.CreateEncryptor(); // INITIALIZE A NEW ENCYPTOR
                            using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                            {
                                fsInput.CopyTo(cs); // ENCRYPT AND SAVE ENCRYPTED DATA TO "EncryptedFile"
                            }
                        }
                    }
                }

                Messages message = new Messages(); // CREATE NEW MESSAGE 
                message.messageBody = outputFilePath; // MESAGE BODY WILL BE THE OUTPUT FILE PATH
                _context.Messages.Add(message); // SAVE MESSAGE TO DATABASE
                _context.SaveChanges(); 
            }

            else // DUPLICATED FILE DETECTED
            {
                // DELETE DUPLICATE MESSAGE FIRST -> THEN CONTINUE
                _context.Messages.Where(m => m.messageBody == filePath).ExecuteDelete();

                // SAME PROCEDURES AS ABOVE
                // SAME PROCEDURES AS ABOVE
                // SAME PROCEDURES AS ABOVE

                string outputFilePath = Path.Combine(
                   Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "EncryptedFile" + Path.GetExtension(filePath));

                // ENCRYPTION
                using (FileStream fsInput = new FileStream(filePath, FileMode.Open))
                {
                    using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create))
                    {
                        using (AesManaged aes = new AesManaged())
                        {
                            aes.GenerateKey();
                            aes.GenerateIV();

                            var sender = _context.Users.FirstOrDefault(u => u.username == "A");
                            sender.aesKey = aes.Key;
                            sender.aesIV = aes.IV;
                            _context.Entry(sender).State = EntityState.Modified;
                            _context.SaveChanges(); // SAVE aes key and aes ıv

                            // PERFORM ENCRYPTION
                            ICryptoTransform encryptor = aes.CreateEncryptor();
                            using (CryptoStream cs = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
                            {
                                fsInput.CopyTo(cs);
                            }
                        }
                    }
                }

                Messages message = new Messages();
                message.messageBody = outputFilePath;
                _context.Messages.Add(message);
                _context.SaveChanges();
            }



        }

        // DECRYPT SELECTED FILE WITH SYMMETRIC AES DECRYPTION
        [HttpGet("symmetricDecryption")]
        public void symmetricDecryption (string filePath)
        {
            // SET OUTPUT FILE PATH AS "DecryptedFile"
            // DECRYPTED FILE WILL BE SAVED TO YOUR LOCAL DESKTOP
            string outputFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "DecryptedFile" + Path.GetExtension(filePath));

            // DECRYPTION PROCESS
            using (FileStream fsInput = new FileStream(filePath, FileMode.Open)) // OPEN SELECTED FILE IN THE FILEPATH
            {
                using (FileStream fsOutput = new FileStream(outputFilePath, FileMode.Create)) // CREATE A NEW OUTPUT FILE AS "DecrpytedFile"
                {
                    using (AesManaged aes = new AesManaged())
                    {
                        // RETRIEVE THE SYMMETRIC AES KEY FROM USER A (SENDER)
                        
                        var sender = _context.Users.FirstOrDefault(u=>u.username=="A"); // FIND THE INFO ABOUT SENDER
                        aes.Key = sender.aesKey; // GET THE SYMMETRIC AES KEY
                        aes.IV = sender.aesIV;

                        // PERFORM DECRYPTION
                        ICryptoTransform decryptor = aes.CreateDecryptor(); // CREATE A NEW DECRYPTOR
                        using (CryptoStream cs = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                        {
                            fsInput.CopyTo(cs); // SAVE DECRYPTED DATA AS "DecrpytedFile" TO LOCAL DESKTOP
                        }
                    }
                }
            }
        }


        // ENCRYPT FILE WITH AES SYMMETRIC ENCRYPTION THEN CREATE DIGITAL SIGNATURE
        [HttpGet("signAndEncrypt")]
        public string signAndEncrypt(string filePath)
        {
            try
            {
                symmetricEncrypion(filePath); // ENCRYPT FILE WITH AES THEN SAVE TO DATABASE
                createDigitalSignature(filePath); // CREATE DIGITAL SIGNATURE OF THE FILE THEN SAVE TO DATABASE

                // GET SAVED FILE AFTER SYMMETRIC ENCRYPTION FUNCTION CALL
                Messages encryptedFile = _context.Messages.Where(m=>m.messageBody.Contains("EncryptedFile")).FirstOrDefault();

                // GET SAVED FILE AFTER CREATE DIGITAL SIGNATURE FUNCTION CALL
                Messages signedFile = _context.Messages.Where(m => m.messageBody == filePath).FirstOrDefault();

                // CREATE NEW MESSAGE
                Messages combined = new Messages();

                // COMBINE THE DIGITAL SIGNATURE + ENCRYPED FILE PATH (AS MESSAGE BODY)
                combined.messageBody = encryptedFile.messageBody;
                combined.digitalSignature = signedFile.digitalSignature;

                // DELETE SAVED FILE AFTER THE FUNCTION CALLS
                _context.Messages.Where(m => m.messageBody.Contains("EncryptedFile")).ExecuteDelete();
                _context.Messages.Where(m => m.messageBody == filePath).ExecuteDelete();

                // SAVE COMBINED MESSAGE (BOTH SIGNED AND ENCRYPTED) TO DATABASE
                _context.Messages.Add(combined);
                _context.SaveChanges();
                return "SUCCESS"; // RETURN STATUS MESSAGE
            }
            catch(Exception ex)
            {
                return "FAILED"; // RETURN STATUS MESSAGE

            }
        }


        // FIRST DECRYPT THEN VERIFY DIGITAL SIGNATURE OF THE SELECTED FILE
        [HttpGet("decryptAndVerify")]
        public string decryptAndVerify(string filePath)
        {
            try
            {
                symmetricDecryption(filePath); // AES DECRYPTION
                verifyDigitalSignature(filePath); // SIGNATURE VERIFICATION
                
                return "SUCCESS"; // RETURN STATUS MESSAGE
            }
            catch(Exception ex)
            { 
                return "FAILED"; // RETURN STATUS MESSAGE

            }
        }

        // CREATES DIGITAL SIGNATURE FOR SELECTED FILE
        [HttpGet("createDigitalSignature")]
        public string createDigitalSignature(string filePath) 
        {

            var checkDuplicate = _context.Messages.FirstOrDefault(m => m.messageBody == filePath); // CHECK DUPLICATE FILES
            if (checkDuplicate == null) // NO DUPLICATED FILE THEN CONTINUE
            {
                string hashedMessage = hashMessage(filePath); // HASH THE FILE IN THE GIVEN FILE PATH INPUT
                var sender = _context.Users.FirstOrDefault(u => u.username == "A"); // FIND USER "A" (SENDER)
                var receiver = _context.Users.FirstOrDefault(u => u.username == "B"); // FIND USER "B" (RECEIVER)

                // INITIALIZE ASYMMETRIC RSA ALGORITHM WITH 4096 BIT KEY LENGTH
                RSACryptoServiceProvider csp = new RSACryptoServiceProvider(4096); 

                var privateKey = csp.ExportParameters(false); // GET PRIVATE KEY
                var publicKey = csp.ExportParameters(true); // GET PUBLIC KEY

                // GET PRIVATE KEY AS STRING
                string privKeyString;
                {

                    var sw = new System.IO.StringWriter();
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    xs.Serialize(sw, privateKey);
                    privKeyString = sw.ToString(); // GET PRIVATE KEY AS STRING
                }

                // SAVE TO SENDER (USER A)'S PRIVATE KEY
                sender.privateKey = privKeyString;

                // GET PUBLIC KEY AS STRING
                string pubKeyString;
                {
                    var sw = new System.IO.StringWriter();
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    xs.Serialize(sw, publicKey);
                    pubKeyString = sw.ToString(); // GET PUBLIC KEY AS STRING
                }

                // SAVE TO SENDER (USER A)'S PUBLIC KEY
                sender.publicKey = pubKeyString;

                _context.Entry(sender).State = EntityState.Modified;
                _context.SaveChanges(); // SAVE PUBLIC & PRIVATE KEY OF SENDER TO THE DATABASE

                // LOAD PRIVATE KEY TO THE RSA ALGORITHM (TO ENCRYPT HASHED MESSAGE WITH SENDER'S PRIVATE KEY)
                csp = new RSACryptoServiceProvider();
                csp.ImportParameters(privateKey); // IMPORT PRIVATE KEY

                // HASHED MESSAGE
                var plainTextData = hashedMessage;

                // GET BYTES 
                var bytesPlainTextData = Encoding.Unicode.GetBytes(plainTextData);

                // APPLY PKCS 1.5 PADDING AND ENCRYPT THE HASHED MESSAGE
                var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

                // GET THE STRING REPRESENTATION OF THE CYPHER TEXT
                var cypherText = Convert.ToBase64String(bytesCypherText);

                // SAVE MESSAGE BODY + SENDER PRIVATE KEY-ENCRYPTED HASHED MESSAGE
                Messages signedMessage = new Messages();
                signedMessage.digitalSignature = cypherText;
                signedMessage.messageBody = filePath;
                _context.Messages.Add(signedMessage);
                _context.SaveChanges();

                List<string> messageBody = new List<string>();

                messageBody.Add(filePath); // PLAIN TEXT MESSAGE
                messageBody.Add(cypherText); // SENDER PRIVATE KEY ENCRYPTED HASHED MESSAGE

                return cypherText; // RETURN 

            }

            else // DUPLICATED FILE DETECTED
            {
                // DELETE DUPLICATE FILE FROM DB
                _context.Messages.Where(m=>m.messageBody == filePath).ExecuteDelete();
                _context.SaveChanges(true);

                // SAME OPERATIONS 
                string hashedMessage = hashMessage(filePath); // HASH THE FILE IN THE GIVEN FILE PATH INPUT

                var sender = _context.Users.FirstOrDefault(u => u.username == "A"); // FIND USER "A"
                var receiver = _context.Users.FirstOrDefault(u => u.username == "B"); // FIND USER "B"

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider(4096);

                var privateKey = csp.ExportParameters(false); // GET PRIVATE KEY
                var publicKey = csp.ExportParameters(true); // GET PUBLIC KEY

                string privKeyString;
                {

                    var sw = new System.IO.StringWriter();
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    xs.Serialize(sw, privateKey);
                    privKeyString = sw.ToString(); // GET PRIVATE KEY AS STRING
                }

                sender.privateKey = privKeyString;

                string pubKeyString;
                {
                    var sw = new System.IO.StringWriter();
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    xs.Serialize(sw, publicKey);
                    pubKeyString = sw.ToString(); // GET PUBLIC KEY AS STRING
                }

                sender.publicKey = pubKeyString;

                _context.Entry(sender).State = EntityState.Modified;
                _context.SaveChanges(); // SAVE PUBLIC & PRIVATE KEY TO THE DATABASE

                // LOAD PRIVATE KEY TO THE RSA (TO ENCRYPT HASHED MESSAGE WITH SENDER'S PRIVATE KEY)
                csp = new RSACryptoServiceProvider();
                csp.ImportParameters(privateKey); // IMPORT PRIVATE KEY

                // HASHED MESSAGE
                var plainTextData = hashedMessage;

                // GET BYTES 
                var bytesPlainTextData = Encoding.Unicode.GetBytes(plainTextData);

                // APPLY PKCS 1.5 PADDING AND ENCRYPT THE HASHED MESSAGE
                var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

                // GET THE STRING REPRESENTATION OF THE CYPHER TEXT
                var cypherText = Convert.ToBase64String(bytesCypherText);

                // SAVE MESSAGE BODY + SENDER PRIVATE KEY-ENCRYPTED HASHED MESSAGE
                Messages signedMessage = new Messages();
                signedMessage.digitalSignature = cypherText;
                signedMessage.messageBody = filePath;
                _context.Messages.Add(signedMessage);
                _context.SaveChanges();

                List<string> messageBody = new List<string>();

                messageBody.Add(filePath); // PLAIN TEXT MESSAGE
                messageBody.Add(cypherText); // SENDER PRIVATE KEY ENCRYPTED HASHED MESSAGE

                return cypherText;

            }

           
        }

        // FUNCTION THAT CHECKS DIGITAL SIGNATURE
        [HttpGet("checkDigitalSignature")]
        public string checkDigitalSignature(Messages message)
        {
            // CONVERT MESSAGE TO BYTE ARRAY
            var bytesCypherText = Convert.FromBase64String(message.digitalSignature); 

            var sender = _context.Users.FirstOrDefault(e => e.username == "A"); // GET THE SENDER DATA

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(sender.publicKey); // DECRYPT THE DIGITAL SIGNATURE WITH SENDER'S PUBLIC KEY

                try
                {
                    byte[] decryptedData = rsa.Decrypt(bytesCypherText, false); // DECRYPTION PROCESS
                    string hashedMessageBody = hashMessage(message.messageBody); // GET THE HASH VALUE OF THE MESSAGE BODY (PLAIN TEXT)
                    string decryptedSignature = Encoding.Unicode.GetString(decryptedData);

                    if (hashedMessageBody == decryptedSignature) // IF HASHED MESSAGE BODY = DECRYPTED DIGITAL SIGNATURE
                    {
                        return "VERIFIED";

                    }
                    else // IF NOT THEN MESSAGE IS CHANGED 
                    {
                        return "NOT VERIFIED";
                    }
                }
                catch (Exception ex)
                {
                    return "NOT VERIFIED";

                }               
            }
        }

        // TAKE A FILE PATH THEN VERIFY DIGITAL SIGNATURE OF THE FILE 
        [HttpGet("verifyDigitalSignature")]
        public string verifyDigitalSignature(string message)
        {
            var messageData = _context.Messages.FirstOrDefault(m => m.messageBody == message); // FIND THE MESSAGE DATA FROM MESSAGE BODY
            if (messageData == null)
            {
                return "Cannot find the message !";

            }
            else
            {
                return checkDigitalSignature(messageData);  // CALL SIGNATURE-CHECKER FUNCTION ABOVE

            }

        }


       
        // CALCULATE THE SHA-512 HASH VALUE OF GIVEN FILE 
        [HttpGet("hashMessage")]
        public string hashMessage(string filePath) // Take sender's (A) private key than sign it
        {
            
            using (SHA512 hash = SHA512.Create()) // CREATE SHA-512
            {
                
                using (FileStream stream = System.IO.File.Open(filePath,FileMode.Open)) // OPEN FILE
                {
                    byte[] hashBytes = hash.ComputeHash(stream);  // HASH THE MESSAGE CONVERTED TO BYTE ARRAY
                    StringBuilder stringBuilder = new StringBuilder();
                    for (int i = 0; i < hashBytes.Length; i++)
                    {
                        stringBuilder.Append(hashBytes[i].ToString("x2")); // CONVERT CALCUALTED HASH BYTE[] TO STRING
                    }
                    return stringBuilder.ToString(); // RETURN HASHED VALUE

                }
            }
        }

        // GET ALL USERS INFO FROM DATABASE
        [HttpGet("getAll")]
        public async Task<ActionResult<List<Users>>> getAll()
        {
            List<Users> list = await _context.Users.ToListAsync();
            if (list.Count == 0 || list == null)
            {
                return BadRequest("No registered users found in database");

            }
            return list;

        }

    }
}

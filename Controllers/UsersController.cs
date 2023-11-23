using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PUBLIC_KEY_INFRASTRUCTURE.Context;
using PUBLIC_KEY_INFRASTRUCTURE.Entities;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml.Linq;

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


        static string Generate2048BitString()
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] randomBytes = new byte[256]; // 2048 bits / 8 bits per byte = 256 bytes
                rng.GetBytes(randomBytes);

                // Convert the random bytes to a string representation
                StringBuilder stringBuilder = new StringBuilder();
                foreach (byte b in randomBytes)
                {
                    stringBuilder.Append(b.ToString("X2")); // Hexadecimal representation
                }

                return stringBuilder.ToString();
            }
        }

        [HttpGet("deneme")]
        public void deneme()
        {
            var sender = _context.Users.FirstOrDefault(u=>u.username == "A");

            
            using (RSA rsa = RSA.Create())
            {

                //Get the public and private key
                string publicKeyString = "MIIBCgKCAQEAwO+gC1T6RbysX40oUYs6M/DbXsnY4N4xF0qRnw8tG+vqk8+x5B3EN+7+BKwLfZQxky2o1IvmpJbTleRyPE/zcQKqz0nH+85w1vuvT4iXnhZg6lkNBNLcqILb3RD3Un5F+CkMgAWoy/A9M0Xf3pqWg6mvA6uLEPq2Z"; // Replace this with your actual public key string
                                                                                                                                                                                                                                                                                                 //string privateKeyString ="acacxascascascascascs"; // Replace this with your actual private key string

                var message = _context.Messages.ToList()[0];
                
                

                string pemX509 = "-----BEGIN PUBLIC KEY-----"
                +publicKeyString+
                "-----END PUBLIC KEY-----";

                //rsa.ImportFromPem(pemX509);

                //var decryptedBytes = rsa.Decrypt(
                  //Convert.FromBase64String(Convert.ToBase64String(Convert.FromBase64String(message.digitalSignature))),
                  //RSAEncryptionPadding.Pkcs1
                //);



                
                //publicKeyString.Replace('_', '/').Replace('-', '+');

                //rsa.ImportFromPem(pemX509);

                // Import the keys from the strings
                rsa.ImportRSAPublicKey(Encoding.UTF8.GetBytes(pemX509), out _);
                //rsa.ImportRSAPrivateKey(Convert.FromBase64String(), out _);

                
                // The string to be encrypted and decrypted
                string originalString = "Hello, this is a test string.";

                // Encrypt the string using the public key
                byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(originalString), RSAEncryptionPadding.OaepSHA256);
                string encryptedString = Convert.ToBase64String(encryptedData);

                System.Diagnostics.Debug.WriteLine("Encrypted String: " + encryptedString);

                // Decrypt the encrypted string using the private key
                byte[] decryptedData = rsa.Decrypt(Convert.FromBase64String(encryptedString), RSAEncryptionPadding.OaepSHA256);
                string decryptedString = Encoding.UTF8.GetString(decryptedData);

                System.Diagnostics.Debug.WriteLine("Decrypted String: " + decryptedString);
                
            }
            
            
        }

        [HttpGet("createDigitalSignature")]
        public List<string> createDigitalSignature(string message) 
        {
            string hashedMessage = hashMessage(message); // HASH MESSAGE BODY WITH SHA - 512 

            var sender = _context.Users.FirstOrDefault(u => u.username == "A"); // FIND USER "A"

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);

            var privateKey = csp.ExportParameters(true);
            var publicKey = csp.ExportParameters(false);

            string privKeyString;
            {
                //we need some buffer
                var sw = new System.IO.StringWriter();
                //we need a serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //serialize the key into the stream
                xs.Serialize(sw, privateKey);
                //get the string from the stream
                privKeyString = sw.ToString();
            }

            sender.privateKey = privKeyString;

            string pubKeyString;
            {
                //we need some buffer
                var sw = new System.IO.StringWriter();
                //we need a serializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //serialize the key into the stream
                xs.Serialize(sw, publicKey);
                //get the string from the stream
                pubKeyString = sw.ToString();
            }


            sender.publicKey = pubKeyString;

            _context.Entry(sender).State = EntityState.Modified;
            _context.SaveChanges();

            //converting it back
            {
                //get a stream from the string
                var sr = new System.IO.StringReader(privKeyString);
                //we need a deserializer
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                //get the object back from the stream
                publicKey = (RSAParameters)xs.Deserialize(sr);
            }

            //conversion for the private key is no black magic either ... omitted

            //we have a public key ... let's get a new csp and load that key
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(privateKey);

            //we need some data to encrypt
            var plainTextData = message;

            //for encryption, always handle bytes...
            var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);

            //apply pkcs#1.5 padding and encrypt our data 
            var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);

            //we might want a string representation of our cypher text... base64 will do
            var cypherText = Convert.ToBase64String(bytesCypherText);


            _context.Messages.ExecuteDelete();
            _context.SaveChanges();

            // SAVE MESSAGE BODY + SENDER PRIVATE KEY-ENCRYPTED HASHED MESSAGE
            Messages signedMessage = new Messages();
            signedMessage.digitalSignature = cypherText;
            signedMessage.messageBody = message;
            _context.Messages.Add(signedMessage);
            _context.SaveChanges();

            List<string> messageBody = new List<string>();

            messageBody.Add(message); // PLAIN TEXT MESSAGE
            messageBody.Add(cypherText); // SENDER PRIVATE KEY ENCRYPTED HASHED MESSAGE
            return messageBody;
        }


        [HttpGet("verifyDigitalSignature")]
        public byte[] verifyDigitalSignature(Messages message)
        {
            var bytesCypherText = Convert.FromBase64String(message.digitalSignature);

            var sender = _context.Users.FirstOrDefault(e => e.username == "A");

            

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(sender.publicKey);

                byte[] decryptedData = rsa.Decrypt(bytesCypherText,false);

                return decryptedData;
            }
            
        }

        [HttpGet("test")]
        public string test()
        {
            var message = _context.Messages.ToList()[0];
            byte[] decrypt = verifyDigitalSignature(message);
            return Encoding.UTF8.GetString(decrypt);
        }

        [HttpGet("hashMessage")]
        public string hashMessage(string message) // Take sender's (A) private key than sign it
        {
            using (SHA512 hash = SHA512.Create()) 
            {
                byte[] bytes = Encoding.UTF8.GetBytes(message); // CONVERT MESSAGE INPUT INTO BYTE ARRAY
                byte[] hashBytes = hash.ComputeHash(bytes);  // HASH THE MESSAGE CONVERTED TO BYTE ARRAY

                StringBuilder stringBuilder = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    stringBuilder.Append(hashBytes[i].ToString("x2")); // CONVERT CALCUALTED HASH BYTE[] TO STRING
                }

                return stringBuilder.ToString(); // RETURN HASHED VALUE

            }
        }


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

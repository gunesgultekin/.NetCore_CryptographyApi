namespace PUBLIC_KEY_INFRASTRUCTURE.Entities
{
    // DATABASE TABLE ATTRIBUTES AND ENTITY FRAMEWORK MAPPING
    public class Users
    {
        public int id {  get; set; }
        public string username { get; set; }
        public string? publicKey { get; set; }
        public string? privateKey { get; set; }
        public byte[]? aesKey { get; set; }
        public byte[]? aesIV { get; set; }
    }
}

namespace PUBLIC_KEY_INFRASTRUCTURE.Entities
{
    public class Users
    {
        public int id {  get; set; }
        public string username { get; set; }
        public string? publicKey { get; set; }
        public string? privateKey { get; set; }
    }
}

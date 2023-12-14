namespace PUBLIC_KEY_INFRASTRUCTURE.Entities
{
    // DATABASE TABLE ATTRIBUTES AND ENTITY FRAMEWORK MAPPING
    public class Messages
    {
        public int id { get; set; }
        public string? messageBody { get; set; }
        public string? digitalSignature { get; set; }
    }
}

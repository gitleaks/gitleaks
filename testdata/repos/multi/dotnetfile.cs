namespace Test.rzandonai.Request
{

    public class ConfigKeys : ConfigurationSection
    {

        /// <summary>
        /// Random but not Key
        /// </summary>
        [ConfigurationProperty("partner", DefaultValue = "21108")]
        public string Partner
        {
            get { return (string)this["partner"]; }
            set { this["partner"] = value; }
        }

        /// <summary>
        /// API Key
        /// </summary>
        [ConfigurationProperty("apiKey", DefaultValue = "2f12779e593499b981beb7fe9644bb955b9dada7")]
        public string ApiKey
        {
            get { return (string)this["apiKey"]; }
            set { this["apiKey"] = value; }
        }

        /// <summary>
        /// Random but not Key
        /// </summary>
        [DefaultValue("40045123827")]
        public string MachineCode
        {
            get { return (string)this["machineCode"]; }
            set { this["machineCode"] = value; }
        }

        /// <summary>
        /// Key
        /// </summary>
        [DefaultValue("6a7r756enumfbu")]
        public string MachineKey
        {
            get { return (string)this["machineKey"]; }
            set { this["machineKey"] = value; }
        }

        /// <summary>
        /// empty key
        /// </summary>
        [DefaultValue("")]
        public string MachineKey2
        {
            get { return (string)this["machineKey2"]; }
            set { this["machineKey2"] = value; }
        }
    }
}
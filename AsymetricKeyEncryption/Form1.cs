using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace AsymetricKeyEncryption
{
    public partial class Form1 : Form
    {
        private const int RsaKeySize = 2048;
        private const string publicKeyFileName = "RSA.Pub";
        private const string privateKeyFileName = "RSA.Private";

        private string basePathToStoreKeys;

        public Form1()
        {
            InitializeComponent();

            basePathToStoreKeys = Directory.GetCurrentDirectory();
        }

        // Generate keys
        private void button1_Click(object sender, EventArgs e)
        {
            GenerateKeys(basePathToStoreKeys);
        }

        // Encrypt textbox content
        private void button2_Click(object sender, EventArgs e)
        {
            var encryptedString = Encrypt(textBox1.Text, Path.Combine(basePathToStoreKeys, publicKeyFileName));

            textBox2.Text = encryptedString;
        }

        // Decrypt textbox content
        private void button3_Click(object sender, EventArgs e)
        {
            var decryptedString = Decrypt(textBox2.Text, Path.Combine(basePathToStoreKeys, privateKeyFileName));

            textBox2.Text = decryptedString;
        }

        /// <summary>
        /// Generates private and public keys in XML format in the given path.
        /// </summary>
        public void GenerateKeys(string path)
        {
            using (var rsa = new RSACryptoServiceProvider(RsaKeySize))
            {
                try
                {
                    // Get private and public keys.
                    var publicKey = rsa.ToXmlString(false);
                    var privateKey = rsa.ToXmlString(true);

                    // Save to disk
                    File.WriteAllText(Path.Combine(path, publicKeyFileName), publicKey);
                    File.WriteAllText(Path.Combine(path, privateKeyFileName), privateKey);

                    MessageBox.Show(string.Format("RSA keys generated in path: {0}\\ [{1}, {2}]", path, publicKeyFileName, privateKeyFileName));
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Encrypts plain text given a RSA public key file path.
        /// </summary>
        /// <param name="plainText">The text to encrypt.</param>
        /// <param name="pathToPublicKey">The path for the public key to use for encryption.</param>
        /// <returns>A 64 bit encoded string representing the encrypted data.</returns>
        public string Encrypt(string plainText, string pathToPublicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(RsaKeySize))
            {
                try
                {
                    // Load the public key
                    var publicXmlKey = File.ReadAllText(pathToPublicKey);
                    rsa.FromXmlString(publicXmlKey);

                    var bytesToEncrypt = System.Text.Encoding.Unicode.GetBytes(plainText);

                    var bytesEncrypted = rsa.Encrypt(bytesToEncrypt, false);

                    return Convert.ToBase64String(bytesEncrypted);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Decrypts encrypted text given a RSA private key file path.
        /// </summary>
        /// <param name="encryptedText">The text that is encrypted</param>
        /// <param name="pathToPrivateKey">The path for the private key to use for encryption.</param>
        /// <returns>a string with unencrypted data</returns>
        public string Decrypt(string encryptedText, string pathToPrivateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(RsaKeySize))
            {
                try
                {
                    // Load the keys
                    var privateXmlKey = File.ReadAllText(pathToPrivateKey);
                    rsa.FromXmlString(privateXmlKey);

                    var bytesEncrypted = Convert.FromBase64String(encryptedText);

                    var bytesPlainText = rsa.Decrypt(bytesEncrypted, false);

                    return System.Text.Encoding.Unicode.GetString(bytesPlainText);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}

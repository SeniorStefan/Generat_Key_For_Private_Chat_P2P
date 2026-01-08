using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Generat_Key
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly string appFolder = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "MySecureChat");

        public MainWindow()
        {
            InitializeComponent();
            Directory.CreateDirectory(appFolder);
        }

        private void GenerateKeys_Click(object sender, RoutedEventArgs e)
        {
            string password = PasswordBox.Password;
            if (string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Введите пароль для защиты закрытого ключа.");
                return;
            }

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                string publicKey = rsa.ToXmlString(false);
                string privateKey = rsa.ToXmlString(true);

                // Зашифруем закрытый ключ паролем
                string encryptedPrivateKey = EncryptPrivateKey(privateKey, password);

                // Сохранение
                File.WriteAllText(System.IO.Path.Combine(appFolder, "publicKey.xml"), publicKey);
                File.WriteAllText(System.IO.Path.Combine(appFolder, "privateKey.enc"), encryptedPrivateKey);

                MessageBox.Show("Ключи сгенерированы и сохранены!");
            }
        }

        private string EncryptPrivateKey(string privateKey, string password)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(password);
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = SHA256.Create().ComputeHash(keyBytes);
                aes.GenerateIV();
                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(privateKey);
                    byte[] encrypted = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    byte[] combined = new byte[aes.IV.Length + encrypted.Length];
                    Buffer.BlockCopy(aes.IV, 0, combined, 0, aes.IV.Length);
                    Buffer.BlockCopy(encrypted, 0, combined, aes.IV.Length, encrypted.Length);
                    return Convert.ToBase64String(combined);
                }
            }
        }

        private void PasswordBox_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            if(!Regex.IsMatch(e.Text, "^[a-zA-Z0-9]+$"))
            {
                e.Handled = true;
                System.Windows.MessageBox.Show("Пароль от ключа требует ввода только латинских символов либо цифр");
            }
            else
            {
                e.Handled = false;
            }
        }
    }
}

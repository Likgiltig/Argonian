using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Konscious.Security.Cryptography;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
namespace Argonian
{
    public partial class Form1 : Form
    {
        private HashSet<string> addedFilePaths = new HashSet<string>();
        private string selectedOption = "Password";
        private string selectedMode = "Encrypt";
        private bool _processingErrorOccurred = false;
        private const int CHUNK_SIZE = 1024 * 1024;
        private const int SALT_SIZE = 16;
        private const int TAG_SIZE = 16;
        private const int IV_SIZE = 12;
        private const int KDF_KEY_DERIVATION_LENGTH = AES_KEY_SIZE + VERIFICATION_HASH_SIZE;
        private const int AES_KEY_SIZE = 32;
        private const int VERIFICATION_HASH_SIZE = 16;
        private const int ARGON2_MEMORY_SIZE_KB = 65536;
        private const int ARGON2_ITERATIONS = 4;
        private static readonly int ARGON2_DEGREE_OF_PARALLELISM = Environment.ProcessorCount > 1 ? 2 : 1;
        private const string LOG_FILE_NAME = "log.txt";
        private const long COMPRESSION_THRESHOLD_BYTES = 5 * 1024 * 1024;
        private const byte COMPRESSION_FLAG_SIZE = 1;
        private const byte COMPRESSION_FLAG_COMPRESSED = 1;
        private const byte COMPRESSION_FLAG_NOT_COMPRESSED = 0;
        public Form1()
        {
            InitializeComponent();
            SetupUI();
        }
        private void SetupUI()
        {
            filePathTextBox.AllowDrop = true;
            filePathTextBox.DragEnter += (sender, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            filePathTextBox.DragDrop += FilePathTextBox_DragDrop;
            radioPassword.Checked = true;
            radioKey.CheckedChanged += OptionRadioButton_CheckedChanged;
            radioPassword.CheckedChanged += OptionRadioButton_CheckedChanged;
            radioEncrypt.Checked = true;
            EventHandler modeChangedHandler = (sender, e) => {if (sender is RadioButton radioButton && radioButton.Checked) selectedMode = radioButton.Text;};
            radioEncrypt.CheckedChanged += modeChangedHandler;
            radioDecrypt.CheckedChanged += modeChangedHandler;
            filePathTextBox.TextChanged += FilePathTextBox_TextChanged;
            buttonClear.Click += ButtonClear_Click;
            buttonExecute.Click += ButtonExecute_Click;
            buttonLog.Click += ButtonLog_Click;
            buttonHelp.Click += ButtonHelp_Click;
            progressBar.Visible = false;
            textDebug.ScrollBars = ScrollBars.Vertical;
            bool hasFiles = !string.IsNullOrEmpty(filePathTextBox.Text);
            buttonExecute.Enabled = hasFiles;
            radioKey.Enabled = hasFiles;
            radioPassword.Enabled = hasFiles;
            radioEncrypt.Enabled = hasFiles;
            radioDecrypt.Enabled = hasFiles;
            buttonClear.Enabled = hasFiles;
            buttonLog.Enabled = File.Exists(LOG_FILE_NAME);
        }
        private void FilePathTextBox_TextChanged(object sender, EventArgs e)
        {
            bool hasFiles = !string.IsNullOrEmpty(filePathTextBox.Text);
            buttonExecute.Enabled = hasFiles;
            radioKey.Enabled = hasFiles;
            radioPassword.Enabled = hasFiles;
            radioEncrypt.Enabled = hasFiles;
            radioDecrypt.Enabled = hasFiles;
            buttonClear.Enabled = hasFiles;
        }
        private void LogAction(string action, string mode, string originalFile, string processedFile, bool success)
        {
            if (!checkBoxLogging.Checked)
            {
                return;
            }
            try
            {
                string logEntry = $"{DateTime.Now}: ({action}) - ({mode}) - \"{originalFile}\" - \"{processedFile}\" - ({(success ? "successful" : "failure")}){Environment.NewLine}";
                File.AppendAllText(LOG_FILE_NAME, logEntry);
            }
            catch (Exception ex)
            {
                UpdateDebug($"Error writing to log file: {ex.Message}");
            }
        }
        private void UpdateDebug(string message)
        {
            if (textDebug.InvokeRequired)
            {
                textDebug.Invoke(new Action<string>(UpdateDebug), message);
            }
            else
            {
                textDebug.AppendText($"{DateTime.Now}: {message}{Environment.NewLine}");
            }
        }
        private void UpdateProgress(int percentage)
        {
            if (progressBar.InvokeRequired)
            {
                progressBar.Invoke(new Action<int>(UpdateProgress), percentage);
            }
            else
            {
                progressBar.Value = Math.Max(progressBar.Minimum, Math.Min(progressBar.Maximum, percentage));
                progressBar.Visible = percentage > 0 && percentage < 100;
            }
        }
        private void FilePathTextBox_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
        }
        private void FilePathTextBox_DragDrop(object sender, DragEventArgs e)
        {
            string[] droppedPaths = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string path in droppedPaths) ProcessPathToAdd(path);
        }
        private void ProcessPathToAdd(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    UpdateDebug($"Adding files from directory: {path}");
                    foreach (string filePath in Directory.GetFiles(path, "*", SearchOption.AllDirectories)) AddFilePathToList(filePath);
                    UpdateDebug($"Finished adding files from directory: {path}");
                }
                else if (File.Exists(path))
                {
                    AddFilePathToList(path);
                }
            }
            catch (Exception ex)
            {
                ShowSingleError($"Error accessing path: {path}\n{ex.Message}");
                UpdateDebug($"Error accessing path: {path} - {ex.Message}");
            }
        }
        private void AddFilePathToList(string filePath)
        {
            string normalizedPath = Path.GetFullPath(filePath).ToLowerInvariant();
            if (addedFilePaths.Add(normalizedPath))
            {
                if (!string.IsNullOrEmpty(filePathTextBox.Text)) filePathTextBox.AppendText(Environment.NewLine);
                filePathTextBox.AppendText(filePath);
                UpdateDebug($"Added file: {filePath}");
                UpdateFileStatsLabels();
            }
            else
            {
                UpdateDebug($"Skipped duplicate file: {filePath}");
            }
        }
        private void OptionRadioButton_CheckedChanged(object sender, EventArgs e)
        {
            if (sender is RadioButton radioButton && radioButton.Checked)
            {
                if (radioButton.Text == "Password" || radioButton.Text == "Key")
                {
                    selectedOption = radioButton.Text;
                }
            }
        }
        private void ButtonClear_Click(object sender, EventArgs e)
        {
            filePathTextBox.Clear();
            addedFilePaths.Clear();
            textDebug.Clear();
            UpdateDebug("File list and debug log cleared.");
            UpdateFileStatsLabels();
        }
        private void ButtonLog_Click(object sender, EventArgs e)
        {
            try
            {
                if (File.Exists(LOG_FILE_NAME))
                {
                    Process.Start("notepad.exe", LOG_FILE_NAME);
                    UpdateDebug("Opened log file.");
                }
            }
            catch (Exception ex)
            {
                ShowSingleError($"Error opening log file: {ex.Message}");
                UpdateDebug($"Error opening log file: {ex.Message}");
            }
        }
        private void ButtonHelp_Click(object sender, EventArgs e)
        {
            string helpText = "Argonian File Encryptor/Decryptor\r\n\r\nHow to Use:\r\n1. Drag and drop files or folders onto the text box.\r\n2. Choose 'Encrypt' or 'Decrypt'.\r\n3. Select 'Password' or 'Key' mode.\r\n4. If using Password, enter and confirm your password.\r\n5. If using Key (Encrypt), a key file will be generated.\r\n6. If using Key (Decrypt), select the key file.\r\n7. Click 'Execute' to start the operation.\r\n\r\nFiles ending with '.encrypted' are skipped during encryption.\r\nOnly files ending with '.encrypted' are processed during decryption.\r\n\r\nImportant: Keep your password or key file safe! Without it, your files cannot be decrypted.\r\n\r\nLogging: Operation results are saved to log.txt in the application directory if enabled.\r\n\nSecure Delete: Overwrite original files multiple times after processing if enabled.\r\n\nCompression: To Reduce file size. (Not currently working)\r\n\nMultithreading: Will speed up process. (Not currently working)\r\n\r\nDisclaimer: Use this software at your own risk. Always back up your important files before processing.";
            MessageBox.Show(this, helpText, "Helpful Message Box", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        private async void ButtonExecute_Click(object sender, EventArgs e)
        {
            _processingErrorOccurred = false;
            selectedOption = radioPassword.Checked ? "Password" : "Key";
            selectedMode = radioEncrypt.Checked ? "Encrypt" : "Decrypt";
            List<string> originalFilesToProcess = addedFilePaths.ToList();
            UpdateDebug($"Starting operation: {selectedMode}, Option: {selectedOption} on {originalFilesToProcess.Count} initial files.");
            UpdateDebug($"Logging: {(checkBoxLogging.Checked ? "Enabled" : "Disabled")}, Secure Delete: {(checkBoxSecureDelete.Checked ? "Enabled" : "Disabled")}, Compression: {(checkBoxCompression.Checked ? "Enabled" : "Disabled")}");
            if (!originalFilesToProcess.Any())
            {
                MessageBox.Show("No files added to process.", "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            SetUIEnabled(false);
            UpdateProgress(1);
            int successCount = 0;
            int failCount = 0;
            int skippedCount = 0;
            List<string> filesToActuallyProcess = new List<string>();
            byte[] keyMaterial = null;
            bool credentialsOk = false;
            TimeSpan elapsed = TimeSpan.Zero;
            Stopwatch stopwatch = null;
            string decryptionPassword = null;
            try
            {
                if (selectedMode == "Encrypt")
                {
                    filesToActuallyProcess = originalFilesToProcess.Where(f => !f.EndsWith(".encrypted", StringComparison.OrdinalIgnoreCase)).ToList();
                    skippedCount = originalFilesToProcess.Count - filesToActuallyProcess.Count;
                    if (skippedCount > 0) UpdateDebug($"{skippedCount} file(s) already ending with .encrypted were skipped.");
                    if (selectedOption == "Password")
                    {
                        string password = ShowPasswordDialog($"Enter Password for {selectedMode}ion", true);
                        if (!string.IsNullOrEmpty(password))
                        {
                            byte[] saltForDerivation = GenerateRandomBytes(SALT_SIZE);
                            var derivedKeys = DeriveKeyWithArgon2(password, saltForDerivation);
                            if (derivedKeys.HasValue)
                            {
                                keyMaterial = new byte[KDF_KEY_DERIVATION_LENGTH];
                                Buffer.BlockCopy(derivedKeys.Value.aesKey, 0, keyMaterial, 0, AES_KEY_SIZE);
                                Buffer.BlockCopy(derivedKeys.Value.verificationHash, 0, keyMaterial, AES_KEY_SIZE, VERIFICATION_HASH_SIZE);
                                credentialsOk = true;
                                Array.Clear(derivedKeys.Value.aesKey, 0, derivedKeys.Value.aesKey.Length);
                                Array.Clear(derivedKeys.Value.verificationHash, 0, derivedKeys.Value.verificationHash.Length);
                                stopwatch = Stopwatch.StartNew();
                                for (int i = 0; i < filesToActuallyProcess.Count; i++)
                                {
                                    string filePath = filesToActuallyProcess[i];
                                    UpdateProgress((int)(((double)i / filesToActuallyProcess.Count) * 98) + 1);
                                    UpdateDebug($"Processing [{selectedMode} / {selectedOption}]: {Path.GetFileName(filePath)}");
                                    bool success = await Task.Run(() => EncryptFile(filePath, keyMaterial, selectedOption, saltForDerivation));
                                    if (success) successCount++; else failCount++;
                                }
                                filesToActuallyProcess.Clear();
                            }
                            Array.Clear(saltForDerivation, 0, saltForDerivation.Length);
                        }
                    }
                    else
                    {
                        byte[] tempKeyMaterial = GenerateRandomBytes(KDF_KEY_DERIVATION_LENGTH);
                        string keyFilePath = ShowSaveKeyDialog();
                        if (!string.IsNullOrEmpty(keyFilePath))
                        {
                            try
                            {
                                File.WriteAllBytes(keyFilePath, tempKeyMaterial);
                                MessageBox.Show($"Key file saved to:\n{keyFilePath}\nKeep this file safe!", "Key Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
                                keyMaterial = tempKeyMaterial;
                                credentialsOk = true;
                                UpdateDebug($"Key file saved: {keyFilePath}");
                                stopwatch = Stopwatch.StartNew();
                                for (int i = 0; i < filesToActuallyProcess.Count; i++)
                                {
                                    string filePath = filesToActuallyProcess[i];
                                    UpdateProgress((int)(((double)i / filesToActuallyProcess.Count) * 98) + 1);
                                    UpdateDebug($"Processing [{selectedMode} / {selectedOption}]: {Path.GetFileName(filePath)}");
                                    bool success = await Task.Run(() => EncryptFile(filePath, keyMaterial, selectedOption));
                                    if (success) successCount++; else failCount++;
                                }
                                filesToActuallyProcess.Clear();
                            }
                            catch (Exception ex)
                            {
                                ShowSingleError($"Error saving key file: {ex.Message}");
                                UpdateDebug($"Error saving key file: {ex.Message}");
                                Array.Clear(tempKeyMaterial, 0, tempKeyMaterial.Length);
                            }
                        }
                        else
                        {
                            UpdateDebug("Save key dialog cancelled.");
                            Array.Clear(tempKeyMaterial, 0, tempKeyMaterial.Length);
                        }
                    }
                }
                else
                {
                    filesToActuallyProcess = originalFilesToProcess.Where(f => f.EndsWith(".encrypted", StringComparison.OrdinalIgnoreCase)).ToList();
                    skippedCount = originalFilesToProcess.Count - filesToActuallyProcess.Count;
                    if (skippedCount > 0) UpdateDebug($"{skippedCount} file(s) not ending with .encrypted were skipped for decryption.");
                    if (selectedOption == "Password")
                    {
                        decryptionPassword = ShowPasswordDialog($"Enter Password for Decryption", false);
                        if (string.IsNullOrEmpty(decryptionPassword))
                        {
                            UpdateDebug("Decryption cancelled (Password dialog cancelled)");
                            failCount = filesToActuallyProcess.Count;
                            credentialsOk = false;
                        }
                        else
                        {
                            credentialsOk = true;
                        }
                    }
                    else
                    {
                        string keyFilePath = ShowOpenKeyDialog("Select Key File");
                        if (!string.IsNullOrEmpty(keyFilePath))
                        {
                            try
                            {
                                byte[] tempKeyMaterial = File.ReadAllBytes(keyFilePath);
                                if (tempKeyMaterial.Length != KDF_KEY_DERIVATION_LENGTH)
                                {
                                    ShowSingleError($"Invalid key file size. Expected {KDF_KEY_DERIVATION_LENGTH} bytes.");
                                    UpdateDebug($"Invalid key file size: {keyFilePath}");
                                    Array.Clear(tempKeyMaterial, 0, tempKeyMaterial.Length);
                                }
                                else
                                {
                                    keyMaterial = tempKeyMaterial;
                                    credentialsOk = true;
                                    UpdateDebug($"Key file loaded: {keyFilePath}");
                                }
                            }
                            catch (Exception ex)
                            {
                                ShowSingleError($"Error reading key file: {ex.Message}");
                                UpdateDebug($"Error reading key file: {ex.Message}");
                            }
                        }
                        else
                        {
                            UpdateDebug("Open key dialog cancelled.");
                        }
                    }
                    if (credentialsOk)
                    {
                        stopwatch = Stopwatch.StartNew();
                        for (int i = 0; i < filesToActuallyProcess.Count; i++)
                        {
                            string filePath = filesToActuallyProcess[i];
                            UpdateProgress((int)(((double)i / filesToActuallyProcess.Count) * 98) + 1);
                            UpdateDebug($"Processing [{selectedMode} / {selectedOption}]: {Path.GetFileName(filePath)}");
                            bool success = await Task.Run(() => DecryptFile(filePath, selectedMode, selectedOption, keyMaterial, decryptionPassword));
                            if (success) successCount++; else failCount++;
                        }
                        filesToActuallyProcess.Clear();
                    }
                }
                if (stopwatch != null)
                {
                    stopwatch.Stop();
                    elapsed = stopwatch.Elapsed;
                }
            }
            catch (Exception ex)
            {
                ShowSingleError($"An unexpected error occurred: {ex.Message}\nCheck debug log.");
                UpdateDebug($"Critical Error in ButtonExecute_Click: {ex}");
            }
            finally
            {
                UpdateProgress(100);
                string summaryMessage = $"{selectedMode}ion Summary ({selectedOption} Mode):\n" +
                                        $"--------------------------\n" +
                                        $"Total Files Selected: {originalFilesToProcess.Count}\n" +
                                        $"Skipped: {skippedCount}\n" +
                                        $"Attempted: {successCount + failCount}\n" +
                                        $"Successful: {successCount}\n" +
                                        $"Failed: {failCount}\n" +
                                        $"Time Taken: {elapsed.TotalSeconds:F2} seconds";
                UpdateDebug($"Operation finished. Summary:\n{summaryMessage}");
                MessageBox.Show(summaryMessage, "Operation Complete", MessageBoxButtons.OK,
                    (failCount > 0 || _processingErrorOccurred) ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
                if (originalFilesToProcess.Count > 0)
                {
                    filePathTextBox.Clear();
                    addedFilePaths.Clear();
                }
                SetUIEnabled(true);
                UpdateProgress(0);
                if (keyMaterial != null) Array.Clear(keyMaterial, 0, keyMaterial.Length);
                if (decryptionPassword != null) decryptionPassword = null;
                GC.Collect();
            }
        }
        private void SetUIEnabled(bool enabled)
        {
            if (this.InvokeRequired) { this.Invoke(new Action(() => SetUIEnabled(enabled))); return; }
            filePathTextBox.Enabled = enabled;
            buttonExecute.Enabled = enabled && !string.IsNullOrEmpty(filePathTextBox.Text);
            buttonClear.Enabled = enabled && !string.IsNullOrEmpty(filePathTextBox.Text);
            this.UseWaitCursor = !enabled;
        }
        private void ShowSingleError(string message)
        {
            if (!_processingErrorOccurred)
            {
                _processingErrorOccurred = true;
                MessageBox.Show(message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            UpdateDebug($"Error Reported: {message}");
        }
        private string ShowPasswordDialog(string title, bool requireConfirmation)
        {
            using (PasswordForm passwordForm = new PasswordForm(title, requireConfirmation))
            {
                return passwordForm.ShowDialog(this) == DialogResult.OK ? passwordForm.Password : null;
            }
        }
        private string ShowSaveKeyDialog()
        {
            using (SaveFileDialog sfd = new SaveFileDialog { Filter = "Key files (*.key)|*.key|All files (*.*)|*.*", Title = "Save Key File", DefaultExt = "key", AddExtension = true, FileName = GenerateRandomFilename(".key") })
            {
                return sfd.ShowDialog(this) == DialogResult.OK ? sfd.FileName : null;
            }
        }
        private string ShowOpenKeyDialog(string title)
        {
            using (OpenFileDialog ofd = new OpenFileDialog { Filter = "Key files (*.key)|*.key|All files (*.*)|*.*", Title = title, DefaultExt = "key" })
            {
                return ofd.ShowDialog(this) == DialogResult.OK ? ofd.FileName : null;
            }
        }
        private (byte[] aesKey, byte[] verificationHash)? DeriveKeyWithArgon2(string password, byte[] salt)
        {
            byte[] derivedKey = null;
            byte[] aesKey = null;
            byte[] verificationHash = null;
            try
            {
                if (string.IsNullOrEmpty(password))
                {
                    UpdateDebug("Password is null or empty");
                    throw new ArgumentNullException(nameof(password));
                }
                if (salt == null || salt.Length != SALT_SIZE)
                {
                    UpdateDebug($"Salt is invalid: {(salt == null ? "null" : salt.Length.ToString())}");
                    throw new ArgumentException($"Salt must be {SALT_SIZE} bytes.", nameof(salt));
                }
                UpdateDebug($"Deriving key with password length: {password.Length}, salt length: {salt.Length}");
                UpdateDebug($"Salt value: {BitConverter.ToString(salt)}");
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                using (var argon2 = new Argon2id(passwordBytes))
                {
                    argon2.Salt = salt;
                    argon2.DegreeOfParallelism = ARGON2_DEGREE_OF_PARALLELISM;
                    argon2.MemorySize = ARGON2_MEMORY_SIZE_KB;
                    argon2.Iterations = ARGON2_ITERATIONS;
                    derivedKey = argon2.GetBytes(KDF_KEY_DERIVATION_LENGTH);
                    UpdateDebug($"Derived key length: {derivedKey.Length}");
                }
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
                aesKey = new byte[AES_KEY_SIZE];
                verificationHash = new byte[VERIFICATION_HASH_SIZE];
                Buffer.BlockCopy(derivedKey, 0, aesKey, 0, AES_KEY_SIZE);
                Buffer.BlockCopy(derivedKey, AES_KEY_SIZE, verificationHash, 0, VERIFICATION_HASH_SIZE);
                UpdateDebug($"AES key part: {BitConverter.ToString(aesKey).Substring(0, Math.Min(20, aesKey.Length))}...");
                UpdateDebug($"Verification hash part: {BitConverter.ToString(verificationHash)}");
                return (aesKey, verificationHash);
            }
            catch (Exception ex)
            {
                ShowSingleError($"Key derivation failed: {ex.Message}");
                UpdateDebug($"Argon2id key derivation error: {ex.ToString()}");
                return null;
            }
            finally
            {
                if (derivedKey != null)
                {
                    Array.Clear(derivedKey, 0, derivedKey.Length);
                    UpdateDebug("Cleared derived key from memory");
                }
            }
        }
        private bool EncryptFile(string inputFilePath, byte[] keyMaterial, string mode, byte[] saltForDerivation = null)
        {
            byte[] saltToUse = null;
            byte[] aesKey = null;
            byte[] verificationHash = null;
            try
            {
                if (keyMaterial == null || keyMaterial.Length != KDF_KEY_DERIVATION_LENGTH)
                {
                    throw new ArgumentException($"Invalid key material length. Expected {KDF_KEY_DERIVATION_LENGTH}.", nameof(keyMaterial));
                }
                if (saltForDerivation != null && saltForDerivation.Length == SALT_SIZE)
                {
                    saltToUse = saltForDerivation;
                    UpdateDebug($"Using provided salt for encryption: {BitConverter.ToString(saltToUse)}");
                }
                else
                {
                    saltToUse = GenerateRandomBytes(SALT_SIZE);
                    UpdateDebug($"Generated new salt for encryption: {BitConverter.ToString(saltToUse)}");
                }
                aesKey = new byte[AES_KEY_SIZE];
                verificationHash = new byte[VERIFICATION_HASH_SIZE];
                Buffer.BlockCopy(keyMaterial, 0, aesKey, 0, AES_KEY_SIZE);
                Buffer.BlockCopy(keyMaterial, AES_KEY_SIZE, verificationHash, 0, VERIFICATION_HASH_SIZE);
                return EncryptFileInternal(inputFilePath, aesKey, verificationHash, saltToUse, mode);
            }
            catch (Exception ex)
            {
                ShowSingleError($"Error encrypting {Path.GetFileName(inputFilePath)}: {ex.Message}");
                UpdateDebug($"EncryptFile Error for {inputFilePath} (Mode: {mode}): {ex.ToString()}");
                LogAction("encrypted", mode, Path.GetFileName(inputFilePath), "(failed)", false);
                return false;
            }
            finally
            {
                if (aesKey != null) Array.Clear(aesKey, 0, aesKey.Length);
                if (verificationHash != null) Array.Clear(verificationHash, 0, verificationHash.Length);
                if (saltForDerivation == null && saltToUse != null) Array.Clear(saltToUse, 0, saltToUse.Length);
            }
        }
        private bool EncryptFileInternal(string inputFilePath, byte[] aesKey, byte[] verificationHash, byte[] saltToWrite, string mode)
        {
            string tempEncryptedFilePath = Path.GetTempFileName();
            string originalFileName = Path.GetFileName(inputFilePath);
            string outputFileName = null;
            byte[] originalFileNameBytes = Encoding.UTF8.GetBytes(originalFileName);
            bool compressFile = false;
            long originalFileSize = new FileInfo(inputFilePath).Length;
            if (checkBoxCompression.Checked && originalFileSize > COMPRESSION_THRESHOLD_BYTES)
            {
                compressFile = true;
                UpdateDebug($"File '{originalFileName}' will be compressed.");
            }
            FileStream inputFileStream = null;
            FileStream outputFileStream = null;
            BinaryWriter writer = null;
            Stream dataStream = null;
            try
            {
                inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
                outputFileStream = new FileStream(tempEncryptedFilePath, FileMode.Create, FileAccess.Write);
                writer = new BinaryWriter(outputFileStream);
                using var cipher = new AesGcm(aesKey);
                UpdateDebug($"Writing salt to file header: {BitConverter.ToString(saltToWrite)}");
                writer.Write(saltToWrite);
                UpdateDebug($"Writing verification hash to file header: {BitConverter.ToString(verificationHash)}");
                writer.Write(verificationHash);
                writer.Write(compressFile ? COMPRESSION_FLAG_COMPRESSED : COMPRESSION_FLAG_NOT_COMPRESSED);
                byte[] fileNameLengthBytes = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(fileNameLengthBytes, originalFileNameBytes.Length);
                writer.Write(fileNameLengthBytes);
                writer.Write(originalFileNameBytes);
                if (compressFile)
                {
                    dataStream = new GZipStream(inputFileStream, CompressionMode.Compress, true);
                }
                else
                {
                    dataStream = inputFileStream;
                }
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = dataStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] iv = GenerateRandomBytes(IV_SIZE);
                    byte[] tag = new byte[TAG_SIZE];
                    byte[] ciphertext = new byte[bytesRead];
                    cipher.Encrypt(iv, buffer.AsSpan(0, bytesRead), ciphertext, tag);
                    writer.Write(iv);
                    writer.Write(tag);
                    writer.Write(BitConverter.GetBytes(bytesRead));
                    writer.Write(ciphertext);
                }
                if (dataStream != inputFileStream)
                {
                    dataStream?.Close();
                    dataStream?.Dispose();
                }
                writer.Close();
                outputFileStream.Close();
                outputFileName = GetUniqueFilename(Path.Combine(Path.GetDirectoryName(inputFilePath), GenerateRandomFilename(".encrypted")));
                int retryCount = 3;
                bool copySuccess = false;
                while (retryCount-- > 0)
                {
                    try
                    {
                        File.Copy(tempEncryptedFilePath, outputFileName, true);
                        copySuccess = true;
                        break;
                    }
                    catch (IOException) when (retryCount > 0)
                    {
                        Thread.Sleep(200);
                    }
                }
                if (!copySuccess)
                {
                    throw new IOException($"Failed to copy temporary file {tempEncryptedFilePath} to {outputFileName} after multiple retries.");
                }
                try
                {
                    File.Delete(tempEncryptedFilePath);
                }
                catch (Exception deleteEx)
                {
                    UpdateDebug($"Warning: Failed to delete temporary file {tempEncryptedFilePath}: {deleteEx.Message}");
                }
                UpdateDebug($"Encrypted '{originalFileName}' to '{Path.GetFileName(outputFileName)}'");
                LogAction("encrypted", mode, originalFileName, Path.GetFileName(outputFileName), true);
                writer?.Dispose();
                outputFileStream?.Dispose();
                inputFileStream?.Dispose();
                if (checkBoxSecureDelete.Checked)
                    SecureDelete(inputFilePath);
                else if (File.Exists(inputFilePath))
                    File.Delete(inputFilePath);
                return true;
            }
            catch (Exception ex)
            {
                if (File.Exists(tempEncryptedFilePath)) File.Delete(tempEncryptedFilePath);
                ShowSingleError($"Encryption failed: {ex.Message}");
                UpdateDebug($"Encryption failed: {ex}");
                string logOriginalFileName = originalFileName ?? Path.GetFileName(inputFilePath);
                LogAction("encrypted", mode, logOriginalFileName, "(failed)", false);
                return false;
            }
            finally
            {
                writer?.Dispose();
                outputFileStream?.Dispose();
                inputFileStream?.Dispose();
            }
        }
        private bool DecryptFile(string encryptedFilePath, string mode, string option, byte[] keyData = null, string password = null)
        {
            byte[] salt = null;
            byte[] storedVerificationHash = null;
            byte[] aesKey = null;
            byte[] verificationHash = null;
            string currentEncryptedFileName = Path.GetFileName(encryptedFilePath);
            try
            {
                using (var headerStream = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read))
                {
                    if (headerStream.Length < SALT_SIZE + VERIFICATION_HASH_SIZE + COMPRESSION_FLAG_SIZE)
                    {
                        UpdateDebug($"File too small: {headerStream.Length} bytes");
                        throw new InvalidDataException("File too small to contain header.");
                    }
                    salt = new byte[SALT_SIZE];
                    int saltBytesRead = headerStream.Read(salt, 0, SALT_SIZE);
                    if (saltBytesRead != SALT_SIZE)
                    {
                        UpdateDebug($"Error reading salt from file header. Expected {SALT_SIZE} bytes, read {saltBytesRead}.");
                        throw new InvalidDataException("Could not read full salt from file header.");
                    }
                    UpdateDebug($"Read salt from file header: {BitConverter.ToString(salt)}");
                    UpdateDebug($"File stream position after reading salt header: {headerStream.Position}");
                    storedVerificationHash = new byte[VERIFICATION_HASH_SIZE];
                    int hashBytesRead = headerStream.Read(storedVerificationHash, 0, VERIFICATION_HASH_SIZE);
                    if (hashBytesRead != VERIFICATION_HASH_SIZE)
                    {
                        UpdateDebug($"Error reading stored verification hash from file header. Expected {VERIFICATION_HASH_SIZE} bytes, read {hashBytesRead}.");
                        throw new InvalidDataException("Could not read full stored verification hash from file header.");
                    }
                    UpdateDebug($"Read stored verification hash from file header: {BitConverter.ToString(storedVerificationHash)}");
                    UpdateDebug($"File stream position after reading stored hash header: {headerStream.Position}");
                }
                if (option == "Password")
                {
                    UpdateDebug($"Using password mode for decryption");
                    var derivedKeys = DeriveKeyWithArgon2(password, salt);
                    if (!derivedKeys.HasValue)
                    {
                        UpdateDebug("Key derivation failed");
                        LogAction("decrypted", option, "(unknown - KDF fail)", currentEncryptedFileName, false);
                        return false;
                    }
                    aesKey = derivedKeys.Value.aesKey;
                    verificationHash = derivedKeys.Value.verificationHash;
                    UpdateDebug($"Computed verification hash: {BitConverter.ToString(verificationHash)}");
                }
                else if (option == "Key")
                {
                    UpdateDebug($"Using key mode for decryption");
                    if (keyData == null || keyData.Length != KDF_KEY_DERIVATION_LENGTH)
                    {
                        UpdateDebug($"Invalid key data: {(keyData == null ? "null" : keyData.Length.ToString())}");
                        throw new ArgumentException("Invalid key data.");
                    }
                    aesKey = new byte[AES_KEY_SIZE];
                    verificationHash = new byte[VERIFICATION_HASH_SIZE];
                    Buffer.BlockCopy(keyData, 0, aesKey, 0, AES_KEY_SIZE);
                    Buffer.BlockCopy(keyData, AES_KEY_SIZE, verificationHash, 0, VERIFICATION_HASH_SIZE);
                    UpdateDebug($"Extracted verification hash from key: {BitConverter.ToString(verificationHash)}");
                }
                else
                {
                    throw new ArgumentException("Invalid option. Must be 'Password' or 'Key'.");
                }
                UpdateDebug($"Stored verification hash: {BitConverter.ToString(storedVerificationHash)}");
                UpdateDebug($"Computed verification hash: {(verificationHash != null ? BitConverter.ToString(verificationHash) : "null")}");
                bool hashesMatch = CompareByteArrays(verificationHash, storedVerificationHash);
                UpdateDebug($"Verification hashes match: {hashesMatch}");
                if (!hashesMatch)
                {
                    UpdateDebug($"{option} verification failed for {currentEncryptedFileName}");
                    LogAction("decrypted", option, "(verification failed)", currentEncryptedFileName, false);
                    return false;
                }
                return DecryptFileInternal(encryptedFilePath, aesKey, option);
            }
            catch (Exception ex)
            {
                ShowSingleError($"Error decrypting {currentEncryptedFileName}: {ex.Message}");
                UpdateDebug($"DecryptFile Error for {encryptedFilePath}: {ex}");
                LogAction("decrypted", option, "(unknown - error)", currentEncryptedFileName, false);
                return false;
            }
            finally
            {
                if (aesKey != null)
                {
                    Array.Clear(aesKey, 0, aesKey.Length);
                    UpdateDebug("Cleared AES key from memory");
                }
                if (verificationHash != null)
                {
                    Array.Clear(verificationHash, 0, verificationHash.Length);
                    UpdateDebug("Cleared verification hash from memory");
                }
                if (salt != null)
                {
                    Array.Clear(salt, 0, salt.Length);
                    UpdateDebug("Cleared salt from memory");
                }
                if (storedVerificationHash != null)
                {
                    Array.Clear(storedVerificationHash, 0, storedVerificationHash.Length);
                    UpdateDebug("Cleared stored verification hash from memory");
                }
            }
        }
        private bool DecryptFileInternal(string encryptedFilePath, byte[] aesKey, string mode)
        {
            string tempDecryptedFilePath = Path.GetTempFileName();
            string decryptedFileNamePath = null;
            string originalFileName = "decrypted_file";
            FileStream inputFileStream = null;
            BinaryReader reader = null;
            FileStream outputFileStream = null;
            Stream finalOutputStream = null;
            try
            {
                inputFileStream = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read);
                reader = new BinaryReader(inputFileStream);
                using var cipher = new AesGcm(aesKey);
                inputFileStream.Seek(SALT_SIZE + VERIFICATION_HASH_SIZE, SeekOrigin.Begin);
                byte compressionFlag = reader.ReadByte();
                bool wasCompressed = compressionFlag == COMPRESSION_FLAG_COMPRESSED;
                int nameLen = BinaryPrimitives.ReadInt32BigEndian(reader.ReadBytes(4));
                byte[] nameBytes = reader.ReadBytes(nameLen);
                originalFileName = Encoding.UTF8.GetString(nameBytes);
                outputFileStream = new FileStream(tempDecryptedFilePath, FileMode.Create, FileAccess.Write);
                if (wasCompressed)
                {
                    finalOutputStream = new GZipStream(outputFileStream, CompressionMode.Decompress, true);
                    UpdateDebug($"Decompressing file '{originalFileName}'.");
                }
                else
                {
                    finalOutputStream = outputFileStream;
                }
                byte[] iv = new byte[IV_SIZE];
                byte[] tag = new byte[TAG_SIZE];
                byte[] chunkSizeBytes = new byte[4];
                while (inputFileStream.Position < inputFileStream.Length)
                {
                    if (reader.Read(iv, 0, IV_SIZE) != IV_SIZE) throw new EndOfStreamException("Could not read full IV.");
                    if (reader.Read(tag, 0, TAG_SIZE) != TAG_SIZE) throw new EndOfStreamException("Could not read full Tag.");
                    if (reader.Read(chunkSizeBytes, 0, 4) != 4) throw new EndOfStreamException("Could not read full chunk size.");
                    int chunkSize = BitConverter.ToInt32(chunkSizeBytes, 0);
                    byte[] ciphertext = reader.ReadBytes(chunkSize);
                    if (ciphertext.Length != chunkSize) throw new EndOfStreamException("Could not read full ciphertext chunk.");
                    byte[] plaintext = new byte[chunkSize];
                    cipher.Decrypt(iv, ciphertext, tag, plaintext);
                    finalOutputStream.Write(plaintext, 0, plaintext.Length);
                }
                if (finalOutputStream != outputFileStream)
                {
                    finalOutputStream?.Close();
                    finalOutputStream?.Dispose();
                }
                outputFileStream.Close();
                decryptedFileNamePath = GetUniqueFilename(Path.Combine(Path.GetDirectoryName(encryptedFilePath), originalFileName));
                int retryCount = 3;
                bool copySuccess = false;
                while (retryCount-- > 0)
                {
                    try
                    {
                        File.Copy(tempDecryptedFilePath, decryptedFileNamePath, true);
                        copySuccess = true;
                        break;
                    }
                    catch (IOException) when (retryCount > 0)
                    {
                        Thread.Sleep(200);
                    }
                }
                if (!copySuccess)
                {
                    throw new IOException($"Failed to copy temporary file {tempDecryptedFilePath} to {decryptedFileNamePath} after multiple retries.");
                }
                try
                {
                    File.Delete(tempDecryptedFilePath);
                }
                catch (Exception deleteEx)
                {
                    UpdateDebug($"Warning: Failed to delete temporary file {tempDecryptedFilePath}: {deleteEx.Message}");
                }
                UpdateDebug($"Decrypted to '{originalFileName}'");
                LogAction("decrypted", mode, originalFileName, Path.GetFileName(encryptedFilePath), true);
                outputFileStream?.Dispose();
                reader?.Close();
                inputFileStream?.Close();
                if (checkBoxSecureDelete.Checked)
                    SecureDelete(encryptedFilePath);
                else if (File.Exists(encryptedFilePath))
                    File.Delete(encryptedFilePath);
                return true;
            }
            catch (Exception ex)
            {
                if (File.Exists(tempDecryptedFilePath)) File.Delete(tempDecryptedFilePath);
                ShowSingleError($"Decryption failed: {ex.Message}");
                UpdateDebug($"Decryption failed: {ex}");
                string logOriginalFileName = originalFileName ?? Path.GetFileName(encryptedFilePath);
                LogAction("decrypted", mode, logOriginalFileName, Path.GetFileName(encryptedFilePath), false);
                return false;
            }
            finally
            {
                outputFileStream?.Dispose();
                reader?.Close();
                inputFileStream?.Close();
            }
        }
        private bool SecureDelete(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return true;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    long len = fs.Length;
                    byte[] randomBuffer = new byte[Math.Min(len, 65536)];
                    byte[] zeroBuffer = new byte[Math.Min(len, 65536)];
                    for (int pass = 0; pass < 3; pass++)
                    {
                        if (pass == 0)
                        {
                            using (var rng = RandomNumberGenerator.Create())
                                rng.GetBytes(randomBuffer);
                        }
                        else if (pass == 1)
                        {
                            for (int i = 0; i < randomBuffer.Length; i++)
                                randomBuffer[i] = 0xFF;
                        }
                        else
                        {
                            randomBuffer = zeroBuffer;
                        }
                        fs.Position = 0;
                        long written = 0;
                        while (written < len)
                        {
                            int toWrite = (int)Math.Min(randomBuffer.Length, len - written);
                            fs.Write(randomBuffer, 0, toWrite);
                            written += toWrite;
                        }
                        fs.Flush(true);
                    }
                }
                File.Delete(filePath);
                UpdateDebug($"Securely deleted (3-pass overwrite): {filePath}");
                return true;
            }
            catch (Exception ex)
            {
                UpdateDebug($"Secure delete failed for {filePath}: {ex.Message}. Attempting standard delete.");
                try
                {
                    if (File.Exists(filePath)) File.Delete(filePath);
                    return true;
                }
                catch (Exception ex2)
                {
                    UpdateDebug($"CRITICAL: Standard delete FAILED for {filePath} after secure delete failed. Initial: {ex.Message}, Fallback: {ex2.Message}");
                    return false;
                }
            }
        }
        private bool CompareByteArrays(byte[] a1, byte[] a2)
        {
            if (a1 == null || a2 == null)
            {
                UpdateDebug("CompareByteArrays: One or both arrays are null");
                return false;
            }
            if (a1.Length != a2.Length)
            {
                UpdateDebug($"CompareByteArrays: Length mismatch {a1.Length} vs {a2.Length}");
                return false;
            }
            UpdateDebug($"Array 1 (first 16 bytes): {BitConverter.ToString(a1.Take(Math.Min(16, a1.Length)).ToArray())}");
            UpdateDebug($"Array 2 (first 16 bytes): {BitConverter.ToString(a2.Take(Math.Min(16, a2.Length)).ToArray())}");
            int diff = 0;
            for (int i = 0; i < a1.Length; i++)
            {
                diff |= a1[i] ^ a2[i];
            }
            bool result = diff == 0;
            UpdateDebug($"Array comparison result: {result}");
            return result;
        }
        private byte[] GenerateRandomBytes(int numberOfBytes)
        {
            byte[] b = new byte[numberOfBytes];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(b);
            return b;
        }
        private string GenerateRandomFilename(string extension)
        {
            return Path.GetRandomFileName().Replace(".", "").Substring(0, 8) + extension;
        }
        private string GetUniqueFilename(string proposedFilePath)
        {
            if (!File.Exists(proposedFilePath)) return proposedFilePath;
            string dir = Path.GetDirectoryName(proposedFilePath);
            string baseName = Path.GetFileNameWithoutExtension(proposedFilePath);
            string ext = Path.GetExtension(proposedFilePath);
            int i = 1;
            string uniquePath;
            do
            {
                uniquePath = Path.Combine(dir, $"{baseName}_{i++}{ext}");
                if (i > 1000)
                    throw new IOException("Cannot generate unique filename after 1000 attempts.");
            } while (File.Exists(uniquePath));
            return uniquePath;
        }
        private void UpdateFileStatsLabels()
        {
            if (labelFiles.InvokeRequired || labelSize.InvokeRequired)
            {
                this.Invoke(new Action(UpdateFileStatsLabels));
                return;
            }
            int fileCount = addedFilePaths.Count;
            long totalSize = 0;
            try
            {
                foreach (string filePath in addedFilePaths)
                {
                    try
                    {
                        if (File.Exists(filePath))
                        {
                            totalSize += new FileInfo(filePath).Length;
                        }
                    }
                    catch (Exception ex)
                    {
                        UpdateDebug($"Error getting size for file {filePath}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                UpdateDebug($"Error calculating total size: {ex.Message}");
                totalSize = 0;
            }
            labelFiles.Text = $"Files added: {fileCount}";
            string fileSize;
            if (totalSize < 1024)
            {
                fileSize = $"{totalSize} Bytes";
            }
            else if (totalSize < 1024 * 1024)
            {
                fileSize = $"{(totalSize / 1024.0):F2} KB";
            }
            else if (totalSize < 1024 * 1024 * 1024)
            {
                fileSize = $"{(totalSize / (1024.0 * 1024.0)):F2} MB";
            }
            else
            {
                fileSize = $"{(totalSize / (1024.0 * 1024.0 * 1024.0)):F2} GB";
            }
            labelSize.Text = $"Total size: {fileSize}";
        }
    }
    public class PasswordForm : Form
    {
        private TextBox passwordTextBox;
        private TextBox confirmPasswordTextBox;
        private Button okButton;
        private bool requireConfirmation;
        public string Password => passwordTextBox?.Text;
        public PasswordForm(string title, bool requireConfirm)
        {
            this.requireConfirmation = requireConfirm;
            InitializeComponentManual(title);
        }
        private void InitializeComponentManual(string title)
        {
            this.Text = title;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterParent;
            this.ClientSize = new Size(400, requireConfirmation ? 200 : 180);
            this.MinimizeBox = false;
            this.MaximizeBox = false;
            this.AutoScaleMode = AutoScaleMode.Font;
            passwordTextBox = new TextBox
            {
                PasswordChar = '*',
                Location = new Point(20, 40),
                Width = 360,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            Label passwordLabel = new Label { Text = "Password:", Location = new Point(20, 20), AutoSize = true };
            okButton = new Button { Text = "OK", DialogResult = DialogResult.OK, Size = new Size(80, 30) };
            okButton.Click += OkButton_Click;
            Button cancelButton = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Size = new Size(80, 30) };
            this.Controls.Add(passwordLabel);
            this.Controls.Add(passwordTextBox);
            this.Controls.Add(okButton);
            this.Controls.Add(cancelButton);
            this.AcceptButton = okButton;
            this.CancelButton = cancelButton;
            if (requireConfirmation)
            {
                confirmPasswordTextBox = new TextBox
                {
                    PasswordChar = '*',
                    Location = new Point(20, 110),
                    Width = 360,
                    Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
                };
                Label confirmPasswordLabel = new Label { Text = "Confirm Password:", Location = new Point(20, 90), AutoSize = true };
                this.Controls.Add(confirmPasswordLabel);
                this.Controls.Add(confirmPasswordTextBox);
                okButton.Location = new Point(180, 160);
                cancelButton.Location = new Point(290, 160);
            }
            else
            {
                okButton.Location = new Point(180, 100);
                cancelButton.Location = new Point(290, 100);
            }
            okButton.Anchor = cancelButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            passwordTextBox.TabIndex = 1;
            if (requireConfirmation)
            {
                confirmPasswordTextBox.TabIndex = 2;
                okButton.TabIndex = 3;
                cancelButton.TabIndex = 4;
            }
            else
            {
                okButton.TabIndex = 2;
                cancelButton.TabIndex = 3;
            }
        }
        private void OkButton_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(passwordTextBox.Text))
            {
                MessageBox.Show(this, "Password cannot be empty.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                this.DialogResult = DialogResult.None;
                passwordTextBox.Focus();
                return;
            }
            if (passwordTextBox.Text.Length < 8)
            {
                MessageBox.Show(this, "Password must be at least 8 characters long.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                this.DialogResult = DialogResult.None;
                passwordTextBox.Focus();
                return;
            }
            if (requireConfirmation && passwordTextBox.Text != confirmPasswordTextBox.Text)
            {
                MessageBox.Show(this, "Passwords do not match.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                this.DialogResult = DialogResult.None;
                confirmPasswordTextBox.Focus();
                confirmPasswordTextBox.SelectAll();
                return;
            }
            this.DialogResult = DialogResult.OK;
        }
    }
}
namespace Argonian
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            panel1 = new Panel();
            radioKey = new RadioButton();
            radioPassword = new RadioButton();
            label1 = new Label();
            panel2 = new Panel();
            radioDecrypt = new RadioButton();
            radioEncrypt = new RadioButton();
            label2 = new Label();
            panel3 = new Panel();
            checkBoxCompression = new CheckBox();
            label3 = new Label();
            checkBoxSecureDelete = new CheckBox();
            checkBoxLogging = new CheckBox();
            buttonExecute = new Button();
            buttonClear = new Button();
            buttonLog = new Button();
            textDebug = new TextBox();
            filePathTextBox = new TextBox();
            buttonHelp = new Button();
            progressBar = new ProgressBar();
            imageList1 = new ImageList(components);
            checkBoxMultithreading = new CheckBox();
            labelFiles = new Label();
            labelSize = new Label();
            panel4 = new Panel();
            panel1.SuspendLayout();
            panel2.SuspendLayout();
            panel3.SuspendLayout();
            panel4.SuspendLayout();
            SuspendLayout();
            // 
            // panel1
            // 
            panel1.Controls.Add(radioKey);
            panel1.Controls.Add(radioPassword);
            panel1.Controls.Add(label1);
            panel1.Location = new Point(17, 20);
            panel1.Margin = new Padding(4, 5, 4, 5);
            panel1.Name = "panel1";
            panel1.Size = new Size(169, 118);
            panel1.TabIndex = 0;
            // 
            // radioKey
            // 
            radioKey.AutoSize = true;
            radioKey.Location = new Point(9, 72);
            radioKey.Margin = new Padding(4, 5, 4, 5);
            radioKey.Name = "radioKey";
            radioKey.Size = new Size(65, 29);
            radioKey.TabIndex = 3;
            radioKey.TabStop = true;
            radioKey.Text = "Key";
            radioKey.UseVisualStyleBackColor = true;
            // 
            // radioPassword
            // 
            radioPassword.AutoSize = true;
            radioPassword.Location = new Point(9, 30);
            radioPassword.Margin = new Padding(4, 5, 4, 5);
            radioPassword.Name = "radioPassword";
            radioPassword.Size = new Size(112, 29);
            radioPassword.TabIndex = 3;
            radioPassword.TabStop = true;
            radioPassword.Text = "Password";
            radioPassword.UseVisualStyleBackColor = true;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Font = new Font("Segoe UI", 9F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label1.Location = new Point(4, 0);
            label1.Margin = new Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new Size(79, 25);
            label1.TabIndex = 3;
            label1.Text = "Method";
            // 
            // panel2
            // 
            panel2.Controls.Add(radioDecrypt);
            panel2.Controls.Add(radioEncrypt);
            panel2.Controls.Add(label2);
            panel2.Location = new Point(194, 20);
            panel2.Margin = new Padding(4, 5, 4, 5);
            panel2.Name = "panel2";
            panel2.Size = new Size(179, 118);
            panel2.TabIndex = 1;
            // 
            // radioDecrypt
            // 
            radioDecrypt.AutoSize = true;
            radioDecrypt.Location = new Point(9, 72);
            radioDecrypt.Margin = new Padding(4, 5, 4, 5);
            radioDecrypt.Name = "radioDecrypt";
            radioDecrypt.Size = new Size(99, 29);
            radioDecrypt.TabIndex = 3;
            radioDecrypt.TabStop = true;
            radioDecrypt.Text = "Decrypt";
            radioDecrypt.UseVisualStyleBackColor = true;
            // 
            // radioEncrypt
            // 
            radioEncrypt.AutoSize = true;
            radioEncrypt.Location = new Point(9, 30);
            radioEncrypt.Margin = new Padding(4, 5, 4, 5);
            radioEncrypt.Name = "radioEncrypt";
            radioEncrypt.Size = new Size(96, 29);
            radioEncrypt.TabIndex = 3;
            radioEncrypt.TabStop = true;
            radioEncrypt.Text = "Encrypt";
            radioEncrypt.UseVisualStyleBackColor = true;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Font = new Font("Segoe UI", 9F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label2.Location = new Point(4, -5);
            label2.Margin = new Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new Size(98, 25);
            label2.TabIndex = 4;
            label2.Text = "Operation";
            // 
            // panel3
            // 
            panel3.Controls.Add(checkBoxCompression);
            panel3.Controls.Add(label3);
            panel3.Controls.Add(checkBoxSecureDelete);
            panel3.Controls.Add(checkBoxLogging);
            panel3.Location = new Point(381, 20);
            panel3.Margin = new Padding(4, 5, 4, 5);
            panel3.Name = "panel3";
            panel3.Size = new Size(154, 157);
            panel3.TabIndex = 2;
            // 
            // checkBoxCompression
            // 
            checkBoxCompression.AutoSize = true;
            checkBoxCompression.Enabled = false;
            checkBoxCompression.Location = new Point(4, 95);
            checkBoxCompression.Margin = new Padding(4, 5, 4, 5);
            checkBoxCompression.Name = "checkBoxCompression";
            checkBoxCompression.Size = new Size(143, 29);
            checkBoxCompression.TabIndex = 5;
            checkBoxCompression.Text = "Compression";
            checkBoxCompression.UseVisualStyleBackColor = true;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Font = new Font("Segoe UI", 9F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label3.Location = new Point(0, -5);
            label3.Margin = new Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new Size(79, 25);
            label3.TabIndex = 5;
            label3.Text = "Options";
            // 
            // checkBoxSecureDelete
            // 
            checkBoxSecureDelete.AutoSize = true;
            checkBoxSecureDelete.Location = new Point(4, 60);
            checkBoxSecureDelete.Margin = new Padding(4, 5, 4, 5);
            checkBoxSecureDelete.Name = "checkBoxSecureDelete";
            checkBoxSecureDelete.Size = new Size(145, 29);
            checkBoxSecureDelete.TabIndex = 4;
            checkBoxSecureDelete.Text = "Secure Delete";
            checkBoxSecureDelete.UseVisualStyleBackColor = true;
            // 
            // checkBoxLogging
            // 
            checkBoxLogging.AutoSize = true;
            checkBoxLogging.Location = new Point(4, 25);
            checkBoxLogging.Margin = new Padding(4, 5, 4, 5);
            checkBoxLogging.Name = "checkBoxLogging";
            checkBoxLogging.Size = new Size(104, 29);
            checkBoxLogging.TabIndex = 3;
            checkBoxLogging.Text = "Logging";
            checkBoxLogging.UseVisualStyleBackColor = true;
            // 
            // buttonExecute
            // 
            buttonExecute.Location = new Point(17, 148);
            buttonExecute.Margin = new Padding(4, 5, 4, 5);
            buttonExecute.Name = "buttonExecute";
            buttonExecute.Size = new Size(90, 38);
            buttonExecute.TabIndex = 3;
            buttonExecute.Text = "Execute";
            buttonExecute.UseVisualStyleBackColor = true;
            // 
            // buttonClear
            // 
            buttonClear.Location = new Point(116, 148);
            buttonClear.Margin = new Padding(4, 5, 4, 5);
            buttonClear.Name = "buttonClear";
            buttonClear.Size = new Size(70, 38);
            buttonClear.TabIndex = 4;
            buttonClear.Text = "Clear";
            buttonClear.UseVisualStyleBackColor = true;
            // 
            // buttonLog
            // 
            buttonLog.Location = new Point(194, 148);
            buttonLog.Margin = new Padding(4, 5, 4, 5);
            buttonLog.Name = "buttonLog";
            buttonLog.Size = new Size(94, 38);
            buttonLog.TabIndex = 5;
            buttonLog.Text = "View Log";
            buttonLog.UseVisualStyleBackColor = true;
            // 
            // textDebug
            // 
            textDebug.BackColor = SystemColors.ActiveCaptionText;
            textDebug.ForeColor = Color.Lime;
            textDebug.Location = new Point(541, 20);
            textDebug.Margin = new Padding(4, 5, 4, 5);
            textDebug.Multiline = true;
            textDebug.Name = "textDebug";
            textDebug.ReadOnly = true;
            textDebug.ScrollBars = ScrollBars.Vertical;
            textDebug.Size = new Size(891, 164);
            textDebug.TabIndex = 6;
            // 
            // filePathTextBox
            // 
            filePathTextBox.Location = new Point(17, 197);
            filePathTextBox.Margin = new Padding(4, 5, 4, 5);
            filePathTextBox.Multiline = true;
            filePathTextBox.Name = "filePathTextBox";
            filePathTextBox.ReadOnly = true;
            filePathTextBox.ScrollBars = ScrollBars.Vertical;
            filePathTextBox.Size = new Size(1415, 669);
            filePathTextBox.TabIndex = 7;
            // 
            // buttonHelp
            // 
            buttonHelp.Location = new Point(297, 148);
            buttonHelp.Margin = new Padding(4, 5, 4, 5);
            buttonHelp.Name = "buttonHelp";
            buttonHelp.Size = new Size(66, 38);
            buttonHelp.TabIndex = 8;
            buttonHelp.Text = "Help";
            buttonHelp.UseVisualStyleBackColor = true;
            // 
            // progressBar
            // 
            progressBar.Location = new Point(21, 882);
            progressBar.Margin = new Padding(4, 5, 4, 5);
            progressBar.Name = "progressBar";
            progressBar.Size = new Size(1413, 38);
            progressBar.TabIndex = 9;
            // 
            // imageList1
            // 
            imageList1.ColorDepth = ColorDepth.Depth32Bit;
            imageList1.ImageSize = new Size(16, 16);
            imageList1.TransparentColor = Color.Transparent;
            // 
            // checkBoxMultithreading
            // 
            checkBoxMultithreading.AutoSize = true;
            checkBoxMultithreading.Enabled = false;
            checkBoxMultithreading.Location = new Point(386, 150);
            checkBoxMultithreading.Margin = new Padding(4, 5, 4, 5);
            checkBoxMultithreading.Name = "checkBoxMultithreading";
            checkBoxMultithreading.Size = new Size(154, 29);
            checkBoxMultithreading.TabIndex = 6;
            checkBoxMultithreading.Text = "Multithreading";
            checkBoxMultithreading.UseVisualStyleBackColor = true;
            // 
            // labelFiles
            // 
            labelFiles.AutoSize = true;
            labelFiles.Location = new Point(0, 0);
            labelFiles.Margin = new Padding(4, 0, 4, 0);
            labelFiles.Name = "labelFiles";
            labelFiles.Size = new Size(121, 25);
            labelFiles.TabIndex = 10;
            labelFiles.Text = "Files added: 0";
            // 
            // labelSize
            // 
            labelSize.AutoSize = true;
            labelSize.Location = new Point(150, 0);
            labelSize.Margin = new Padding(4, 0, 4, 0);
            labelSize.Name = "labelSize";
            labelSize.Size = new Size(133, 25);
            labelSize.TabIndex = 11;
            labelSize.Text = "Total size: 0 MB";
            // 
            // panel4
            // 
            panel4.BackColor = SystemColors.MenuBar;
            panel4.BorderStyle = BorderStyle.FixedSingle;
            panel4.Controls.Add(labelFiles);
            panel4.Controls.Add(labelSize);
            panel4.Location = new Point(1050, 840);
            panel4.Margin = new Padding(4, 5, 4, 5);
            panel4.Name = "panel4";
            panel4.Size = new Size(353, 27);
            panel4.TabIndex = 12;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(10F, 25F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1451, 927);
            Controls.Add(panel4);
            Controls.Add(checkBoxMultithreading);
            Controls.Add(progressBar);
            Controls.Add(buttonHelp);
            Controls.Add(filePathTextBox);
            Controls.Add(textDebug);
            Controls.Add(buttonLog);
            Controls.Add(buttonClear);
            Controls.Add(buttonExecute);
            Controls.Add(panel3);
            Controls.Add(panel2);
            Controls.Add(panel1);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            Icon = (Icon)resources.GetObject("$this.Icon");
            Margin = new Padding(4, 5, 4, 5);
            Name = "Form1";
            Text = "Argonian v2";
            panel1.ResumeLayout(false);
            panel1.PerformLayout();
            panel2.ResumeLayout(false);
            panel2.PerformLayout();
            panel3.ResumeLayout(false);
            panel3.PerformLayout();
            panel4.ResumeLayout(false);
            panel4.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Panel panel1;
        private RadioButton radioKey;
        private RadioButton radioPassword;
        private Label label1;
        private Panel panel2;
        private RadioButton radioDecrypt;
        private RadioButton radioEncrypt;
        private Label label2;
        private Panel panel3;
        private Label label3;
        private CheckBox checkBoxCompression;
        private CheckBox checkBoxSecureDelete;
        private CheckBox checkBoxLogging;
        private Button buttonExecute;
        private Button buttonClear;
        private Button buttonLog;
        private TextBox textDebug;
        private TextBox filePathTextBox;
        private Button buttonHelp;
        private ProgressBar progressBar;
        private ImageList imageList1;
        private CheckBox checkBoxMultithreading;
        private Label labelFiles;
        private Label labelSize;
        private Panel panel4;
    }
}

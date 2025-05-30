# **Argonian**

Argonian is a graphical Windows application designed for encrypting and decrypting files using either a password or a key file. It provides a simple drag-and-drop interface for selecting files and folders to process.

![Screenshot](https://github.com/user-attachments/assets/4af55d60-1f6e-431c-953e-7fa714bb74ad)

I have included all the code:
* **code.cs** - Contains all the functions and logic.
* **code.Designer.cs** - Contains all the graphical element configurations

## **Features**

* **Encryption/Decryption:** Securely encrypt and decrypt your files.  
* **Method Selection:** Choose between password-based or key-based encryption/decryption.  
* **Drag and Drop:** Easily add files and folders by dragging them onto the application window.  
* **Secure Delete:** Option to securely overwrite original files after processing.  
* **Logging:** Record operation results to a log file (log.txt).  
* **File Statistics:** Displays the number of files added and their total size.  
* **Progress Bar:** Visual feedback on the processing progress.  
* **Help Section:** Built-in help message explaining how to use the application.

*(Note: Features like Compression and Multithreading are present in the UI but does not work currently.)*

## **How to Use**

1. **Add Files:** Drag and drop the files or folders you want to encrypt or decrypt onto the main text area.  
2. **Select Operation:** Choose either 'Encrypt' or 'Decrypt' using the radio buttons.  
3. **Select Method:** Choose 'Password' or 'Key' depending on your preferred method.  
   * **Password:** You will be prompted to enter and confirm a password (for encryption) or enter the password (for decryption).  
   * **Key:** For encryption, a key file (.key) will be generated. For decryption, you will need to select the previously generated key file.  
4. **Select Options:** Check the boxes for desired options like 'Logging' or 'Secure Delete'.  
5. **Execute:** Click the 'Execute' button to start the process.

## **Important Notes**

* **Password/Key Security:** Keep your password or key file extremely safe. Without the correct password or key, your encrypted files cannot be recovered.  
* **Encryption Skipping:** Files already ending with .encrypted will be skipped during the encryption process.  
* **Decryption Requirement:** Only files ending with .encrypted will be processed during decryption.  
* **Log File:** If logging is enabled, operation details are saved to log.txt in the application's directory.  

## **Building and Running**

* **Build the Project using the code:** I would suggest creating a new Visual Studio project and integrating the code to the project (code.cs, code.Designer.cs)
* **Run the executable:** The executable is compressed in to three parts and require zero installation or requirements to run.

## **Disclaimer:** Use this software at your own risk. Always back up your important files before processing.

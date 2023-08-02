import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import sys
import subprocess
import threading

def timerDecorator(func):
    def wrapper(*args, **kwargs):
        import time
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print('Time elapsed: ' + str(end - start) + ' seconds')
        return result
    return wrapper

class Encripter:

    EXTENSION_ENCRYPTED = '.enc'
    ENCRYPT_FILENAMES = True
    ENCRYPT_FOLDER_NAMES = True
    REMOVE_AFTER_ENCRYPT = True
    REMOVE_AFTER_DECRYPT = True
    
    MAX_THREADS = 10

    def __init__(self, password):
        self.password = password
        self.setLogger()
    
    def setLogger(self, logger='encripter'):
        # log to file and console
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(levelname)s %(message)s',
            handlers=[
                logging.FileHandler("log.log"),
                logging.StreamHandler()
            ]
        )

        return logging.getLogger(logger)
    
    def generate_key(self):
        password = self.password.encode()
        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key
    
    def encrypt(self, data: bytes):
        key = self.generate_key()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
        ct = encryptor.update(data) + encryptor.finalize()
        return base64.b64encode(iv + ct)
    
    def decrypt(self, data: bytes):
        key = self.generate_key()
        data = base64.b64decode(data)
        iv = data[:16]
        ct = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data) + unpadder.finalize()
        return data
    
    def encrypt_file(self, file: str) -> str:

        fileBck = file

        logging.info("Encrypting file: '" + file + "'")

        try:
            with open(file, 'rb') as f:
                data = f.read()
            
            # Encrypt data
            data = self.encrypt(data)

            # Encrypt filename
            filename = file.split('\\')[-1]
            filename  = self.encrypt(filename.encode()).decode().replace('/', '-')
            pathWithFilename = file.replace('\\' + file.split('\\')[-1], '') + '\\' + filename + self.EXTENSION_ENCRYPTED

            with open(pathWithFilename , 'wb') as f:
                f.write(data)
            
            if self.REMOVE_AFTER_ENCRYPT:
                os.remove(fileBck)
        
        except Exception as e:
            logging.error("Error encrypting file: '" + file + "'")
            logging.error(e)
            return None

        logging.info("File encrypted: '" + pathWithFilename + "'")

        return pathWithFilename
    
    def decrypt_file(self, file):
        fileBck = file

        if not file.endswith(self.EXTENSION_ENCRYPTED):
            logging.error("Error decrypting file: '" + file + "'")
            logging.error("File is not encrypted")
            return None

        logging.info("Decrypting file: '" + file + "'")

        try:
            with open(file, 'rb') as f:
                data = f.read()
        
            # Decrypt data
            data = self.decrypt(data)

            separado = file.split('\\')

            separado[-1] = separado[-1][:-len(self.EXTENSION_ENCRYPTED)].replace('-', '/')
            separado[-1] = self.decrypt(separado[-1]).decode()
        
            # Write decrypted data to file
            with open('\\'.join(separado), 'wb') as f:
                f.write(data)
            
            if self.REMOVE_AFTER_DECRYPT:
                os.remove(fileBck)
            
        except Exception as e:
            logging.error("Error decrypting file: '" + file + "'")
            logging.error(e)
            return None

        logging.info("File decrypted: '" + '\\'.join(separado) + "'")

        return '\\'.join(separado)
    
    def encrypt_files (self, files: list):
        for file in files:
            self.encrypt_file(file)

    def decrypt_files (self, files: list):
        for file in files:
            self.decrypt_file(file)
    
    def decrypt_folder_name(self, folder: str):
        folderSplited = folder.split('\\')
        folderSplited[-1] = self.decrypt(folderSplited[-1].replace('-', '/').encode()).decode()
        return '\\'.join(folderSplited)

    def encrypt_folder_name(self, folder: str):
        folderSplited = folder.split('\\')
        folderSplited[-1] = self.encrypt(folderSplited[-1].encode()).decode().replace('/', '-')
        return '\\'.join(folderSplited)
    
    
    @timerDecorator
    def encrypt_folder(self, folder: str):
        threads = []
        allPaths = []
        allFiles = []

        logging.info("Start encrypting folder: '" + folder + "'")

        try:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    path = os.path.join(root, file)
                    allFiles.append(path)

                for dir in dirs:
                    path = os.path.join(root, dir)
                    allPaths.append(path)
        except Exception as e:
            logging.error("Error encrypting folder: '" + folder + "'")
        
        logging.info("Start encrypting files")
        if (len(allFiles) % self.MAX_THREADS) == 0:
            files_per_thread = len(allFiles) // self.MAX_THREADS
        else:
            files_per_thread = len(allFiles) // self.MAX_THREADS + 1

        for i in range(self.MAX_THREADS):
            if i == self.MAX_THREADS - 1:
                files = allFiles[i * files_per_thread:]
            else:
                files = allFiles[i * files_per_thread:(i + 1) * files_per_thread]
            t = threading.Thread(target=self.encrypt_files, args=(files,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to finish
        for t in threads:
            t.join()

        logging.info("Start encrypting folder names")
        try:
            allPaths.reverse()
            for path in allPaths:
                pathOriginal = path
                path = self.encrypt_folder_name(path)
                print("renaming: " + pathOriginal + " to: " + path)
                os.rename(pathOriginal, path)
        
        except Exception as e:
            logging.error("Error encrypting folder names: '" + folder + "'")
        
        logging.info("End encrypting folder: '" + folder + "'")
    
    @timerDecorator
    def decrypt_folder(self, folder: str):
        logging.info("Start decrypting folder: '" + folder + "'")
        allPaths = []
        allFiles = []
        threads = []

        try:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    path = os.path.join(root, file)
                    allFiles.append(path)

                for dir in dirs:
                    path = os.path.join(root, dir)
                    allPaths.append(path)
        except Exception as e:
            logging.error("Error decrypting folder: '" + folder + "'")

        logging.info("Start decrypting files")
        
        if(len(allFiles) % self.MAX_THREADS == 0):
            files_per_thread = len(allFiles) // self.MAX_THREADS
        else:
            files_per_thread = len(allFiles) // self.MAX_THREADS + 1
    
        for i in range(self.MAX_THREADS):
            if i == self.MAX_THREADS - 1:
                files = allFiles[i * files_per_thread:]
            else:
                files = allFiles[i * files_per_thread:(i + 1) * files_per_thread]

            t = threading.Thread(target=self.decrypt_files, args=(files,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to finish
        for t in threads:
            t.join()
        
        logging.info("Start decrypting folder names")
        try:
            allPaths.reverse()
            for path in allPaths:
                pathOriginal = path
                path = self.decrypt_folder_name(path)
                print("renaming: " + pathOriginal + " to: " + path)
                os.rename(pathOriginal, path)
            
        except Exception as e:
            logging.error("Error decrypting folder names: " + folder)

if __name__ == '__main__':
    encripter = Encripter(input('Password: '))  
    
    if len(sys.argv) > 1 and (sys.argv[1] == '-d' or sys.argv[1] == '--decrypt') and len(sys.argv) > 2: 
        encripter.decrypt_folder(sys.argv[2])
    elif len(sys.argv) > 1 and (sys.argv[1] == '-e' or sys.argv[1] == '--encrypt') and len(sys.argv) > 2:
        encripter.encrypt_folder(sys.argv[2])
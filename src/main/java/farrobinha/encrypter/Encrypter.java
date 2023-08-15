package farrobinha.encrypter;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.util.Base64;

public class Encrypter {

    private Logger logger;
    private SecretKey secretKey;

    public Encrypter(String password, String salt) throws NoSuchAlgorithmException, IOException {
        this.logger = Logger.getLogger(Encrypter.class.getName());
        this.secretKey = generateSecretKey(password, salt);
    }

    public Encrypter(String password) throws NoSuchAlgorithmException, IOException {
        this(password, "0000000000000000");
    }

    private SecretKey generateSecretKey(String password, String salt) throws NoSuchAlgorithmException, IOException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");

        } catch (Exception e) {
            throw new IOException("Error generating secret key", e);
        }
    }

    public byte[] encrypt(byte[] data) throws IOException {
        try {
            // String salt = "your_salt_value"; // Replace with a unique salt
            // salt = b'\x00' * 16

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);

            byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
            byte[] encryptedData = cipher.doFinal(data);

            byte[] ivPlusData = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, ivPlusData, 0, iv.length);
            System.arraycopy(encryptedData, 0, ivPlusData, iv.length, encryptedData.length);

            return ivPlusData;

        } catch (Exception e) {
            throw new IOException("Error encrypting data", e);
        }
    }

    public byte[] decrypt(byte[] data) throws IOException {
        try {
            // Extract IV
            byte[] iv = new byte[16];
            System.arraycopy(data, 0, iv, 0, 16);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, this.secretKey, new IvParameterSpec(iv));

            byte[] decryptedData = cipher.doFinal(data, 16, data.length - 16);

            return decryptedData;

        } catch (Exception e) {
            throw new IOException("Error decrypting data", e);
        }
    }

    public String encrypt(String data) throws IOException {
        byte[] encryptedData = encrypt(data.getBytes());
        return new String(encryptedData);
    }

    public String decrypt(String data) throws IOException {
        byte[] decryptedData = decrypt(data.getBytes());
        return new String(decryptedData);
    }

    public String encryptFileName(String fileName) throws IOException {
        try {
            byte[] encryptedBytes = encrypt(fileName.getBytes(StandardCharsets.UTF_8));
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
            return encryptedBase64.replace("/", "_").replace("+", "-"); // Ajuste de caracteres para uso em nome de
                                                                        // arquivo
        } catch (IOException e) {
            throw new IOException("Error encrypting file name", e);
        }
    }

    public String decryptFileName(String encryptedFileName) throws IOException {
        try {
            // Ajuste de caracteres
            encryptedFileName = encryptedFileName.replace("_", "/").replace("-", "+");
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedFileName);
            byte[] decryptedBytes = decrypt(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IOException("Error decrypting file name", e);
        }
    }

    public File encryptFile(File file) throws IOException {
        // Read file content
        byte[] fileContent = Files.readAllBytes(Paths.get(file.getAbsolutePath()));

        // Encrypt content
        byte[] encryptedContent = encrypt(fileContent);

        // Encrypt file name
        String encryptedFileName = encryptFileName(file.getName());

        String filePath = file.getAbsolutePath().replace(file.getName(), "");
        filePath = filePath + encryptedFileName + ".enc";

        // Write the encrypted content to the encrypted file
        Files.write(Paths.get(filePath), encryptedContent);

        // remove the original file
        file.delete();

        return new File(filePath);
    }

    public File decryptFile(File file) throws IOException {
        // Read file content
        byte[] fileContent = Files.readAllBytes(Paths.get(file.getAbsolutePath()));

        // Decrypt content
        byte[] decryptedContent = decrypt(fileContent);

        // Decrypt file name
        String decryptedFilename = decryptFileName(file.getName().replace(".enc", ""));

        String filePath = file.getAbsolutePath().replace(file.getName(), "");
        filePath = filePath + decryptedFilename;

        // Write the decrypted content to the decrypted file
        Files.write(Paths.get(filePath), decryptedContent);

        // remove the original file
        file.delete();

        return new File(filePath);
    }

}

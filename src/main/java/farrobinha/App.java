package farrobinha;

import java.io.File;

import farrobinha.encrypter.Encrypter;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) throws Exception {
        Encrypter encrypter = new Encrypter("YOUR_PASSWORD_HERE");
        // convert String "123456789" into bytes[]
        byte[] bytes = "123456789".getBytes();
        byte[] enc = encrypter.encrypt(bytes);
        System.out.println("Encrypted: " + new String(enc));
        byte[] dec = encrypter.decrypt(enc);
        System.out.println("Decrypted: " + new String(dec));

        File fileEncrypted = encrypter.encryptFile(new File("C:\\Users\\berna\\Projects\\AES-Encryption\\sessionsTests\\test\\test.txt"));
        System.out.println(
                "--- File encryption ---\n"
                + "\tEncrypted file: " + fileEncrypted.getAbsolutePath()
                        + "\n\t" + "Encrypted file name: " + fileEncrypted.getName()
                        + "\n\t" + "Exists: " + fileEncrypted.exists());

        System.out.println("PRESS ENTER TO DECRYPT FILE");
        System.in.read();

        File file2 = encrypter.decryptFile(fileEncrypted);
        System.out.println("Decrypted file: " + file2.getAbsolutePath()); // "C:\\Users\\berna\\Projects\\AES-Encryption\\ola.txt

    }
}

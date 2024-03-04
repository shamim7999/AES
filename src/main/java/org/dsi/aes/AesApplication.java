package org.dsi.aes;

import org.dsi.aes.securty.Aes;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import javax.crypto.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


@SpringBootApplication
public class AesApplication {

    public static void main(String[] args) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {


        ConfigurableApplicationContext run = SpringApplication.run(AesApplication.class, args);

        Aes aes = run.getBean(Aes.class);

        String input = "This mode is an extension of the CTR mode. The GCM has received significant attention and is recommended by NIST. The GCM model outputs ciphertext and an authentication tag. The main advantage of this mode, compared to other operation modes of the algorithm, is its efficiency.";

        String cipherText = aes.encrypt(input);

        System.out.println("Cipher Text: "+cipherText+"\n\n");

        String plainText = aes.decrypt(cipherText);

        System.out.println("Plain Text: "+plainText+"\n\n");


        File file = new File("/home/shamim/Desktop/test.txt");

        File encryptedFile = aes.encryptFile(file);
        File decryptedFile = aes.decryptFile(encryptedFile);
    }

}

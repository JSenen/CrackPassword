package service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.commons.codec.binary.Base64;

public class CrackPassword {

    private static final int ITERATIONS = 20000;
    private static final int KEY_LENGTH = 256;
    private static String path = null;
    private static BufferedReader reader = null;

    public static void main(String[] args) throws IOException {
        System.out.println(" _____                    _    ______   ___                                      _ \n" +
                "/  __ \\                  | |   | ___ \\ / _ \\                                    | |\n" +
                "| /  \\/ _ __  __ _   ___ | | __| |_/ // /_\\ \\ ___  ___ __      __ ___   _ __  __| |\n" +
                "| |    | '__|/ _` | / __|| |/ /|  __/ |  _  |/ __|/ __|\\ \\ /\\ / // _ \\ | '__|/ _` |\n" +
                "| \\__/\\| |  | (_| || (__ |   < | |    | | | |\\__ \\\\__ \\ \\ V  V /| (_) || |  | (_| |\n" +
                " \\____/|_|   \\__,_| \\___||_|\\_\\\\_|    \\_| |_/|___/|___/  \\_/\\_/  \\___/ |_|   \\__,_");
        System.out.println("=====================================================================================");
        System.out.println("*       PBKDF2 (Password-Based Key Derivation Function 2) decode                    *");
        System.out.println("*       Number of interactions 2000                                                 *");
        System.out.println("*       salt use                                                                    *");
        System.out.println("*       HMAC + SHA1 exit hash                                                       *");
        System.out.println("=====================================================================================");

        System.out.println("🔍 Working and catching data to begin...");

        Scanner selection = new Scanner(System.in);
        System.out.print("Do you want to use the program's wordlist (y) or your txt file (n)? (y/n) > ");
        String decision = selection.next();

        boolean useInternalFile = false;

        if (decision.equalsIgnoreCase("n")) {
            // Pedir la ruta al usuario
            Scanner pathToRockYou = new Scanner(System.in);
            System.out.println("Enter path to rockyou.txt (text file with passwords) > ");
            path = pathToRockYou.next();

            // Verificar si el archivo existe antes de continuar
            File file = new File(path);
            if (!file.exists()) {
                System.err.println("❌ ERROR: rockyou.txt not found. Check the path and try again.");
                return;
            }
        } else {
            // Leer el archivo desde dentro del JAR
            InputStream inputStream = CrackPassword.class.getClassLoader().getResourceAsStream("rockyou.txt");
            if (inputStream == null) {
                System.err.println("❌ ERROR: 'rockyou.txt' not found inside the JAR.");
                return;
            }
            reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            useInternalFile = true;
        }

        // Contar el número de líneas en el archivo
        int lines = 0;
        if (!useInternalFile) {
            try (LineNumberReader lineNumberReader = new LineNumberReader(new FileReader(path))) {
                lineNumberReader.skip(Long.MAX_VALUE);
                lines = lineNumberReader.getLineNumber();
            }
        } else {
            while (reader.readLine() != null) {
                lines++;
            }
            reader.close();
            reader = new BufferedReader(new InputStreamReader(CrackPassword.class.getClassLoader().getResourceAsStream("rockyou.txt"), StandardCharsets.UTF_8));
        }

        System.out.println("✅ Dictionary found.");
        System.out.println("Dictionary contains " + lines + " passwords.");

        // Pedir hash al usuario
        Scanner inHash = new Scanner(System.in);
        System.out.print("Enter hash to decode: ");
        String hashUser = inHash.next();

        // Extraer sal y hash almacenado
        String[] parts = hashUser.split("\\$");
        if (parts.length != 2) {
            System.err.println("❌ ERROR: Invalid hash format.");
            return;
        }
        byte[] salt = Base64.decodeBase64(parts[0]);
        String storedHash = parts[1];

        // Leer el diccionario y probar contraseñas
        try (BufferedReader br = useInternalFile ? reader : new BufferedReader(new FileReader(path))) {
            String password;
            int attempt = 0;

            while ((password = br.readLine()) != null) {
                attempt++;
                float percentage = (attempt * 100) / lines;
                if (attempt % 1 == 0) { // Mostrar progreso
                    System.out.printf("\r%s", "🔄 Attempt: " + attempt + " " + percentage + "% " + password);
                }

                // Generar el hash de la contraseña en prueba
                String generatedHash = hash(password, salt);

                // Comparar con el hash almacenado
                if (generatedHash.equals(storedHash)) {
                    System.out.println("\n🎉 Password found!: " + password);
                    return;
                }
            }
            System.out.println("\n❌ Password not found in the dictionary.");
        } catch (IOException e) {
            System.err.println("❌ Error reading the dictionary: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("❌ Hashing error: " + e.getMessage());
        }
    }

    // Método para generar el hash PBKDF2
    private static String hash(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = factory.generateSecret(new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH));
        return Base64.encodeBase64String(key.getEncoded());
    }
}

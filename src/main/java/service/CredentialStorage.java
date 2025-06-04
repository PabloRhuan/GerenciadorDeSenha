package service;

import model.Credential;
import utils.InputSanitizer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/**
 * Responsável por salvar e carregar credenciais de/para um arquivo criptografado.
 */
public class CredentialStorage {
    private static final Path FILE_PATH = Paths.get("credentials.dat");

    /**
     * Salva uma lista de credenciais em um arquivo criptografado.
     *
     * @param credentials Lista de credenciais a serem salvas.
     * @throws Exception Se ocorrer um erro durante a criptografia ou escrita no arquivo.
     */
    public static void saveCredentials(List<Credential> credentials) throws Exception {
        List<String> encryptedLines = new ArrayList<>();

        for (Credential cred : credentials) {
            String serviceName;
            String username;
            String encryptedPassword;

            try {
                // Garante que todos os campos estejam sanitizados
                serviceName = InputSanitizer.sanitize(cred.serviceName(), 50, false);
                username = InputSanitizer.sanitize(cred.username(), 50, false);
                encryptedPassword = InputSanitizer.sanitize(cred.encryptedPassword(), 128, false);

                String line = String.format("%s,%s,%s", serviceName, username, encryptedPassword);
                encryptedLines.add(EncryptionService.encrypt(line));
            } catch (IllegalArgumentException e) {
                System.err.println("Ignorando credencial inválida: " + e.getMessage());
            }
        }

        // Cria um backup do arquivo atual, se ele existir
        if (Files.exists(FILE_PATH)) {
            Files.copy(FILE_PATH, Paths.get("credentials_backup.dat"), StandardCopyOption.REPLACE_EXISTING);
        }

        try (BufferedWriter writer = Files.newBufferedWriter(FILE_PATH)) {
            for (String line : encryptedLines) {
                writer.write(line);
                writer.newLine();
            }
        } catch (IOException e) {
            throw new IOException("Erro ao escrever no arquivo de credenciais: " + e.getMessage(), e);
        }
    }

    /**
     * Carrega e descriptografa as credenciais do arquivo.
     *
     * @return Lista de credenciais descriptografadas.
     * @throws Exception Se ocorrer um erro durante a leitura ou descriptografia.
     */
    public static List<Credential> loadCredentials() throws Exception {
        List<Credential> credentials = new ArrayList<>();

        if (!Files.exists(FILE_PATH)) {
            return credentials;
        }

        try (BufferedReader reader = Files.newBufferedReader(FILE_PATH)) {
            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    String decrypted = EncryptionService.decrypt(line);
                    String[] parts = decrypted.split(",", 3);

                    if (parts.length == 3) {
                        // Sanitiza e valida as partes descriptografadas
                        String serviceName = InputSanitizer.sanitize(parts[0], 50, false);
                        String username = InputSanitizer.sanitize(parts[1], 50, false);
                        String encryptedPassword = InputSanitizer.sanitize(parts[2], 128, false);

                        credentials.add(new Credential(serviceName, username, encryptedPassword));
                    } else {
                        System.err.println("Formato de linha inválido: " + decrypted);
                    }
                } catch (IllegalArgumentException ex) {
                    System.err.println("Formato de credencial inválido: " + ex.getMessage());
                } catch (Exception ex) {
                    System.err.println("Erro ao descriptografar linha: " + ex.getMessage());
                }
            }
        } catch (IOException e) {
            throw new IOException("Erro ao ler o arquivo de credenciais: " + e.getMessage(), e);
        }

        return credentials;
    }
}

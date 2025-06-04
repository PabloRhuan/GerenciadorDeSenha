package service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * EncryptionService fornece criptografia e descriptografia seguras de dados sensíveis usando AES-GCM.
 * A chave de criptografia é derivada da senha mestre do usuário e de um salt persistente usando PBKDF2.
 * A chave e o salt são mantidos apenas na memória durante a sessão e são limpos ao final da JVM.
 *
 * Uso:
 * - Após a autenticação, chame setSessionKeyAndSalt(masterPassword, salt) para inicializar a chave de sessão.
 *   Observação: `setSessionKeyAndSalt` deve ser chamado antes de encrypt() ou decrypt(), para evitar erros.
 * - Use encrypt() e decrypt() para operações seguras com dados.
 * - O salt persistente é armazenado no arquivo encryption_salt.dat.
 *
 * Notas de Segurança:
 * - Chaves e salts são limpos da memória ao final da execução da JVM via shutdown hook.
 * - AES/GCM/NoPadding é usado para garantir criptografia autenticada.
 */
public class EncryptionService {

	private static String sessionKey = null;
	private static String sessionSalt = null;

	/**
	 * Define a chave e o salt da sessão atual.
	 */
	public static void setSessionKeyAndSalt(String key, String salt) {
		sessionKey = key;
		sessionSalt = salt;
	}

	private static SecretKey getSessionSecretKey() throws Exception {
		if (sessionKey == null || sessionSalt == null) {
			throw new IllegalStateException("A chave e o salt da sessão devem ser definidos antes da criptografia/descriptografia.");
		}
		return getSecretKey(sessionKey, sessionSalt);
	}

	/**
	 * Limpa a chave e o salt da sessão da memória.
	 */
	public static void clearSessionKeyAndSalt() {
		sessionKey = null;
		sessionSalt = null;
	}

	// Chamado automaticamente ao encerrar a JVM para limpar dados sensíveis da memória
	static {
		Runtime.getRuntime().addShutdownHook(new Thread(EncryptionService::clearSessionKeyAndSalt));
	}

	/**
	 * Gera uma chave secreta a partir de uma senha e um salt usando PBKDF2 com HMAC SHA-256.
	 *
	 * @param password a senha usada para derivar a chave
	 * @param salt     o salt como string
	 * @return uma chave secreta adequada para criptografia AES
	 * @throws Exception se ocorrer erro na geração da chave
	 */
	public static SecretKey getSecretKey(String password, String salt) throws Exception {
		byte[] saltBytes = salt.getBytes();
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}

	/**
	 * Criptografa uma string em texto puro usando AES/GCM/NoPadding.
	 * Um IV aleatório é gerado e adicionado ao início dos dados criptografados.
	 * O resultado é codificado em Base64.
	 *
	 * @param strToEncrypt string em texto puro a ser criptografada
	 * @return string codificada em Base64 contendo IV + dados criptografados
	 * @throws Exception se ocorrer falha na criptografia
	 */
	public static String encrypt(String strToEncrypt) throws Exception {
		if (strToEncrypt == null) {
			throw new NullPointerException("A entrada para criptografia não pode ser nula");
		}
		SecretKey key = getSessionSecretKey();
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		byte[] iv = new byte[12];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(iv);
		GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
		byte[] encrypted = cipher.doFinal(strToEncrypt.getBytes());
		byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
		System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
		System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);
		return Base64.getEncoder().encodeToString(encryptedWithIv);
	}

	/**
	 * Descriptografa uma string codificada em Base64 contendo um IV de 12 bytes no início dos dados criptografados.
	 *
	 * @param strToDecrypt string codificada em Base64 contendo IV + dados criptografados
	 * @return string original em texto puro
	 * @throws Exception se ocorrer falha na descriptografia
	 */
	public static String decrypt(String strToDecrypt) throws Exception {
		try {
			SecretKey key = getSessionSecretKey();
			byte[] encryptedIvTextBytes = Base64.getDecoder().decode(strToDecrypt);
			if (encryptedIvTextBytes.length < 13) {
				throw new IllegalArgumentException("Tamanho da entrada criptografada inválido");
			}
			byte[] iv = new byte[12];
			System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
			byte[] encryptedBytes = new byte[encryptedIvTextBytes.length - iv.length];
			System.arraycopy(encryptedIvTextBytes, iv.length, encryptedBytes, 0, encryptedBytes.length);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
			cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
			byte[] decrypted = cipher.doFinal(encryptedBytes);
			return new String(decrypted);
		} catch (Exception e) {
			throw new Exception("Falha na descriptografia", e);
		}
	}

	/**
	 * Utilitário para gerar ou carregar um salt persistente para uso com PBKDF2.
	 *
	 * @return o salt como string (codificado em Base64)
	 * @throws Exception se ocorrer falha na leitura ou gravação do salt
	 */
	public static String getOrCreatePersistentSalt() throws Exception {
		java.nio.file.Path saltPath = java.nio.file.Paths.get("encryption_salt.dat");
		if (java.nio.file.Files.exists(saltPath)) {
			return java.nio.file.Files.readString(saltPath).trim();
		}
		// Gera novo salt aleatório (16 bytes codificados em base64)
		byte[] saltBytes = new byte[16];
		new SecureRandom().nextBytes(saltBytes);
		String salt = Base64.getEncoder().encodeToString(saltBytes);
		java.nio.file.Files.writeString(saltPath, salt);
		return salt;
	}

}

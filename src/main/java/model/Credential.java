package model;

/**
 * Representa uma credencial de usuário salva para um serviço específico.
 */
public record Credential(String serviceName, String username, String encryptedPassword) {
	/**
	 * Constrói uma nova Credential.
	 *
	 * @param serviceName       o nome do serviço (ex.: "Gmail")
	 * @param username          o nome de usuário associado ao serviço
	 * @param encryptedPassword a senha, já criptografada
	 */
	public Credential {
	}

	@Override
	public String toString() {
		return "Serviço: " + serviceName + ", Usuário: " + username;
	}
}

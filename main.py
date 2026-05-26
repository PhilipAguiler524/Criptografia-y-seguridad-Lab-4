from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


# =====================================
# DES
# =====================================

def cifrar_des(key, iv, texto):

    cipher = DES.new(key, DES.MODE_CBC, iv)

    texto_bytes = texto.encode('utf-8')

    texto_padded = pad(texto_bytes, DES.block_size)

    cifrado = cipher.encrypt(texto_padded)

    return base64.b64encode(cifrado)


def descifrar_des(key, iv, texto_cifrado):

    cipher = DES.new(key, DES.MODE_CBC, iv)

    cifrado_bytes = base64.b64decode(texto_cifrado)

    descifrado = cipher.decrypt(cifrado_bytes)

    descifrado = unpad(descifrado, DES.block_size)

    return descifrado.decode('utf-8')


# =====================================
# 3DES
# =====================================

def cifrar_3des(key, iv, texto):

    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    texto_bytes = texto.encode('utf-8')

    texto_padded = pad(texto_bytes, DES3.block_size)

    cifrado = cipher.encrypt(texto_padded)

    return base64.b64encode(cifrado)


def descifrar_3des(key, iv, texto_cifrado):

    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    cifrado_bytes = base64.b64decode(texto_cifrado)

    descifrado = cipher.decrypt(cifrado_bytes)

    descifrado = unpad(descifrado, DES3.block_size)

    return descifrado.decode('utf-8')


# =====================================
# AES-256
# =====================================

def cifrar_aes(key, iv, texto):

    cipher = AES.new(key, AES.MODE_CBC, iv)

    texto_bytes = texto.encode('utf-8')

    texto_padded = pad(texto_bytes, AES.block_size)

    cifrado = cipher.encrypt(texto_padded)

    return base64.b64encode(cifrado)


def descifrar_aes(key, iv, texto_cifrado):

    cipher = AES.new(key, AES.MODE_CBC, iv)

    cifrado_bytes = base64.b64decode(texto_cifrado)

    descifrado = cipher.decrypt(cifrado_bytes)

    descifrado = unpad(descifrado, AES.block_size)

    return descifrado.decode('utf-8')

# =====================================
# Ajuste de la llave
# =====================================

def ajustar_key(key, largo_requerido):

    if len(key) < largo_requerido:

        faltan = largo_requerido - len(key)

        key += get_random_bytes(faltan)

    elif len(key) > largo_requerido:

        key = key[:largo_requerido]

    return key



# =====================================
# MENÚ PRINCIPAL
# =====================================

print("===== ALGORITMOS =====")
print("1. DES")
print("2. 3DES")
print("3. AES-256")

opcion = input("Seleccione algoritmo: ")

texto = input("Ingrese texto a cifrar: ")


# =====================================
# DES
# =====================================

if opcion == "1":

    print("\nDES")
    print("Key: 8 bytes")
    print("IV: 8 bytes")

    key = input("Ingrese key: ").encode('utf-8')

    key = ajustar_key(key, 8)

    print("\nKey ajustada:")
    print(key.hex())
    print("Largo:", len(key))

    iv = input("Ingrese IV: ").encode('utf-8')
    if len(iv) != 8:
        print("Error: IV invalido")
        exit()


    cifrado = cifrar_des(key, iv, texto)

    print("\nTexto cifrado:")
    print(cifrado.decode())

    descifrado = descifrar_des(key, iv, cifrado)

    print("\nTexto descifrado:")
    print(descifrado)


# =====================================
# 3DES
# =====================================

elif opcion == "2":

    print("\n3DES")
    print("Key: 16 o 24 bytes")
    print("IV: 8 bytes")

    key = input("Ingrese key: ").encode('utf-8')
    iv = input("Ingrese IV: ").encode('utf-8')


    # =====================================
    # AJUSTAR KEY
    # =====================================

    # Menor a 16 -> completar a 16
    if len(key) < 16:

        faltan = 16 - len(key)

        key += get_random_bytes(faltan)


    # Entre 16 y 24 -> completar a 24
    elif len(key) > 16 and len(key) < 24:

        faltan = 24 - len(key)

        key += get_random_bytes(faltan)


    # Mayor a 24 -> truncar
    elif len(key) > 24:

        key = key[:24]


    print("\nKey ajustada:")
    print(key.hex())

    print("Largo final:", len(key))


    # =====================================
    # VALIDAR IV
    # =====================================

    if len(iv) != 8:

        print("Error: IV inválido")

        exit()


    # =====================================
    # CIFRAR
    # =====================================

    try:

        key = DES3.adjust_key_parity(key)

        cifrado = cifrar_3des(key, iv, texto)

        print("\nTexto cifrado:")

        print(cifrado.decode())


        descifrado = descifrar_3des(key, iv, cifrado)

        print("\nTexto descifrado:")

        print(descifrado)


    except ValueError:

        print("Error: key inválida para 3DES")



# =====================================
# AES-256
# =====================================

elif opcion == "3":

    print("\nAES-256")
    print("Key: 32 bytes")
    print("IV: 16 bytes")

    key = input("Ingrese key: ").encode('utf-8')

    key = ajustar_key(key, 32)

    print("\nKey ajustada:")
    print(key.hex())
    print("Largo:", len(key))
    iv = input("Ingrese IV: ").encode('utf-8')

    if len(iv) != 16:
        print("Error: AES requiere IV de 16 bytes")
        exit()

    cifrado = cifrar_aes(key, iv, texto)

    print("\nTexto cifrado:")
    print(cifrado.decode())

    descifrado = descifrar_aes(key, iv, cifrado)

    print("\nTexto descifrado:")
    print(descifrado)

else:
    print("Opción inválida")

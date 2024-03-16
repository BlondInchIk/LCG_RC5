import sys 

w = 32  # Размер блока (32 бита)
R = 12  # Количество раундов
key = b'SecretKey'  # Ключ шифрования
strip_extra_nulls = True  # Флаг для удаления дополнительных нулевых байтов

mod = 2 ** w  # Модуль (2^32)
mask = mod - 1  # Маска для битовых операций

def lshift(val, n):
    n %= w
    return ((val << n) & mask) | ((val & mask) >> (w - n))
    # Циклический сдвиг влево для значения `val` на `n` битов

def rshift(val, n):
    n %= w
    return ((val & mask) >> n) | (val << (w - n) & mask)
    # Циклический сдвиг вправо для значения `val` на `n` битов

def const():  # Константы поколения
    if w == 16:
        return 0xB7E1, 0x9E37  # Возвращаемые значения P и Q
    elif w == 32:
        return 0xB7E15163, 0x9E3779B9
    elif w == 64:
        return 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15

def key_align(key):  # Выравнивание ключа
    b = len(key)  # Длина ключа в байтах
    if b == 0:  # Ключ пустой
        c = 1  # Количество блоков ключа (равно 1)
    elif b % (w // 8):  # Если длина ключа не кратна размеру блока
        key += b'\x00' * ((w // 8) - (b % (w // 8)))  # Заполнить ключ нулевыми байтами
        b = len(key)  # Обновить длину ключа
        c = b // (w // 8)  # Количество блоков ключа
    else:
        c = b // (w // 8)  # Количество блоков ключа
    L = [0] * c  # Инициализация списка L
    for i in range(b - 1, -1, -1):
        L[i // (w // 8)] = (L[i // (w // 8)] << 8) + key[i]
        # Преобразование ключа в список L с выравниванием байтов
    return L

def key_extend(L):  # Расширение ключа
    P, Q = const()  # Получение значений P и Q
    return [(P + i * Q) % mod for i in range(2 * (R + 1))]
    # Генерация списка S для шифрования и дешифрования

def shuffle(S, L):  # Перемешивание значений S и L
    i, j, A, B = 0, 0, 0, 0
    for k in range(3 * max(len(L), len(S))):
        A = S[i] = lshift((S[i] + A + B), 3)
        B = L[j] = lshift((L[j] + A + B), A + B)
        i = (i + 1) % len(S)
        j = (j + 1) % len(L)
        # Перемешивание значений S и L с помощью циклического сдвига
    return S, L

def encrypt_block(S, data):  # Шифрование блока данных
    A = int.from_bytes(data[:w // 8], byteorder='little')
    B = int.from_bytes(data[w // 8:], byteorder='little')
    A = (A + S[0]) % mod
    B = (B + S[1]) % mod
    for i in range(1, R + 1):
        A = (lshift((A ^ B), B) + S[2 * i]) % mod
        B = (lshift((A ^ B), A) + S[2 * i + 1]) % mod
        # Выполнение раундов шифрования
    return (A.to_bytes(w // 8, byteorder='little') + B.to_bytes(w // 8, byteorder='little'))
    # Возвращение зашифрованных данных блока

def encrypt_file(inp_file_name, out_file_name):  # Шифрование файла
    with open(inp_file_name, 'rb') as inp, open(out_file_name, 'wb') as out:
        run = True
        while run:
            text = inp.read(w // 4)
            if not text:
                break
            if len(text) != w // 4:  # Если размер блока меньше заданного размера
                text = text.ljust(w // 4, b'\x00')  # Заполнение блока нулевыми байтами
                run = False
            text = encrypt_block(S, text)  # Шифрование блока
            out.write(text)  # Запись зашифрованного блока

def decrypt_block(S, data):  # Дешифрование блока данных
    A = int.from_bytes(data[:w // 8], byteorder='little')
    B = int.from_bytes(data[w // 8:], byteorder='little')
    for i in range(R, 0, -1):
        B = rshift(B - S[2 * i + 1], A) ^ A
        A = rshift(A - S[2 * i], B) ^ B
        # Выполнение раундов дешифрования
    B = (B - S[1]) % mod
    A = (A - S[0]) % mod

    return (A.to_bytes(w // 8, byteorder='little') + B.to_bytes(w // 8, byteorder='little'))
    # Возвращение дешифрованных данных блока

def decrypt_file(inp_file_name, out_file_name):  # Дешифрование файла
    with open(inp_file_name, 'rb') as inp, open(out_file_name, 'wb') as out:
        while True:
            text = inp.read(w // 4)
            if not text:
                break
            text = decrypt_block(S, text)  # Дешифрование блока
            if strip_extra_nulls:
                text = text.rstrip(b'\x00')  # Удаление дополнительных нулевых байтов
            out.write(text)  # Запись расшифрованного блока

L = key_align(key)
S = key_extend(L)
S, L = shuffle(S, L)

if sys.argv[3] == 'encrypt':
    encrypt_file(sys.argv[1], sys.argv[2])  # Шифрование файла
else:
    decrypt_file(sys.argv[1], sys.argv[2])  # Дешифрование файла
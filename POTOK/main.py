import random  # Импортируем модуль random для работы с псевдослучайными числами
import sys  # Импортируем модуль sys для работы с аргументами командной строки

def lcg(seed):
    """
    Линейный конгруэнтный генератор случайных чисел (LCG).

    Принимает семенное значение seed и возвращает генератор последовательности случайных чисел.
    """
    while True:
        seed = (1103515245 * seed + 12345) % (2**31 - 1)  # Формула LCG
        yield seed

def operate_file(input_file, output_file, key_file, operation):
    """
    Производит операцию (шифрование или расшифрование) на файле с использованием поточного шифра LCG.

    Принимает следующие параметры:
    - input_file: имя входного файла
    - output_file: имя выходного файла
    - key_file: имя файла с ключом
    - operation: тип операции ('encrypt' для шифрования, 'decrypt' для расшифрования)
    """
    with open(key_file, 'r') as key_file:
        key = int(key_file.read())  # Читаем ключ из файла

    random.seed(key)  # Инициализируем генератор псевдослучайных чисел с ключом
    key_generator = lcg(random.randint(1, 2**31 - 1))

    with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
        byte = fin.read(1)  # Читаем по одному байту из входного файла
        while byte != b'':
            if operation == 'encrypt':
                processed_byte = ord(byte) ^ (next(key_generator) % 256)  # Выполняем операцию шифрования
            elif operation == 'decrypt':
                processed_byte = ord(byte) ^ (next(key_generator) % 256)  # Выполняем операцию расшифрования

            fout.write(bytes([processed_byte]))  # Записываем обработанный байт в выходной файл
            byte = fin.read(1)  # Читаем следующий байт из входного файла

# Проверяем переданные параметры командной строки
if len(sys.argv) != 5:
    print("Некорректное количество аргументов. Используйте: python file_cipher.py <input_file> <output_file> <key_file> <operation>")
else:
    input_file = sys.argv[1]  # Получаем имя входного файла из аргумента командной строки
    output_file = sys.argv[2]  # Получаем имя выходного файла из аргумента командной строки
    key_file = sys.argv[3]  # Получаем имя файла с ключом из аргумента командной строки
    operation = sys.argv[4]  # Получаем операцию из аргумента командной строки

    operate_file(input_file, output_file, key_file, operation)  # Выполняем операцию на файле

import hashlib
import itertools
import string

def hash_text(text, algorithm):
    hash_object = hashlib.new(algorithm)
    hash_object.update(text.encode('utf-8'))
    return hash_object.hexdigest()

def generate_rainbow_table(algorithm, min_length, max_length, preprocess=False, prefix_length=None):
    rainbow_table = {}
    for length in range(min_length, max_length + 1):
        for word in itertools.product(string.ascii_letters + string.digits, repeat=length):
            word = ''.join(word)
            hashed = hash_text(word, algorithm)
            if preprocess:
                rainbow_table[hashed[:prefix_length]] = word
            else:
                rainbow_table[hashed] = word
    if preprocess:
        # 对哈希值进行排序
        rainbow_table = dict(sorted(rainbow_table.items()))
    return rainbow_table

def save_rainbow_table(table, filename):
    with open(filename, 'w') as file:
        for hashed, word in table.items():
            file.write(f"{hashed}:{word}\n")

def partial_hash_preprocessing(input_file, algorithm, prefix_length):
    with open(input_file, 'r') as file:
        hashes = file.readlines()

    sorted_hashes = sorted(hashes, key=lambda x: x[:prefix_length])

    output_filename = f"sorted_{algorithm}_dic.txt"

    with open(output_filename, 'w') as file:
        for hash_value in sorted_hashes:
            file.write(hash_value)

    print(f"已将排序后的哈希值写入文件 {output_filename}")

def main():
    print("欢迎使用彩虹表生成器！\n")

    algorithms = {
        '1': 'md5',
        '2': 'sha1',
        '3': 'sha224',
        '4': 'sha256',
        '5': 'sha384',
        '6': 'sha512'
    }

    print("请选择操作：")
    print("1. 生成彩虹表")
    print("2. 生成预处理彩虹表")
    print("3. 哈希值预处理")

    operation_choice = input("请选择操作（输入数字）：")

    if operation_choice == '1':
        print("生成彩虹表")
        print("--------------------")

        print("请选择哈希算法：")
        for key, value in algorithms.items():
            print(f"{key}. {value.upper()}")

        algorithm_input = input("请输入选择的哈希算法数字：")
        algorithm = algorithms.get(algorithm_input)
        if not algorithm:
            print("无效的选择，请重新选择！")
            return

        min_length = int(input("请输入最小长度："))
        max_length = int(input("请输入最大长度："))

        rainbow_table = generate_rainbow_table(algorithm, min_length, max_length)

        print("彩虹表生成完成！\n")

        filename = f"{algorithm}_dic.txt"
        save_rainbow_table(rainbow_table, filename)
        print(f"彩虹表已保存到 {filename} 文件中。")

    elif operation_choice == '3':
        print("哈希值预处理")
        print("--------------------")

        input_file = input("请输入包含哈希值的文本文件路径：")

        print("请选择哈希算法：")
        for key, value in algorithms.items():
            print(f"{key}. {value.upper()}")

        algorithm_input = input("请选择哈希算法（输入数字）：")
        algorithm = algorithms.get(algorithm_input)
        if not algorithm:
            print("无效的选择，请重新选择！")
            return

        prefix_length = int(input("请输入哈希值前缀的长度："))

        partial_hash_preprocessing(input_file, algorithm, prefix_length)

    elif operation_choice == '2':
        print("生成预处理彩虹表")
        print("--------------------")

        print("请选择哈希算法：")
        for key, value in algorithms.items():
            print(f"{key}. {value.upper()}")

        algorithm_input = input("请输入选择的哈希算法数字：")
        algorithm = algorithms.get(algorithm_input)
        if not algorithm:
            print("无效的选择，请重新选择！")
            return

        min_length = int(input("请输入最小长度："))
        max_length = int(input("请输入最大长度："))

        prefix_length = int(input("请输入哈希值前缀的长度："))

        rainbow_table = generate_rainbow_table(algorithm, min_length, max_length, preprocess=True)

        print("预处理彩虹表生成完成！\n")

        filename = f"sorted_{algorithm}_dic.txt"
        save_rainbow_table(rainbow_table, filename)
        print(f"预处理彩虹表已保存到 {filename} 文件中。")

    else:
        print("无效的选择，请重新运行并输入正确的数字。")

if __name__ == "__main__":
    main()

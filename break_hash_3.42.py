import hashlib
import os
import itertools

def generate_hash(message, algorithm):
    """
    生成消息的哈希值
    :param message: 明文消息
    :param algorithm: 哈希算法（例如: 'md5', 'sha1', 'sha256' 等）
    :return: 哈希值
    """
    if algorithm == 'md5':
        hash_object = hashlib.md5()
    elif algorithm == 'sha1':
        hash_object = hashlib.sha1()
    elif algorithm == 'sha224':
        hash_object = hashlib.sha224()
    elif algorithm == 'sha256':
        hash_object = hashlib.sha256()
    elif algorithm == 'sha384':
        hash_object = hashlib.sha384()
    elif algorithm == 'sha512':
        hash_object = hashlib.sha512()
    else:
        raise ValueError("Invalid hash algorithm")

    hash_object.update(message.encode('utf-8'))
    return hash_object.hexdigest()

def generate_dictionary(messages, algorithm):
    """
    生成消息-哈希值对并保存到文件
    :param messages: 包含多个明文消息的列表
    :param algorithm: 哈希算法
    """
    with open("result.txt", 'a+') as file:  # 修改为追加模式
        for message in messages:
            hash_value = generate_hash(message, algorithm)
            file.write(f"{hash_value} : {message}\n")  # 将哈希值放在前面
        file.write("---------------------\n")  # 添加分隔符

def set_option():
    while True:
        print("请选择操作：")
        print("1. 生成字典")
        print("2. 破解哈希值")
        option = input("请选择操作（输入1或2）：")
        if option in ['1', '2']:
            return int(option)
        else:
            print("输入无效，请重新输入。")

def main():
    option = set_option()
    if option == 1:
        generate_dictionary_menu()
    elif option == 2:
        hash_cracker_menu()

def generate_dictionary_menu():
    while True:
        print("请选择哈希算法：")
        print("1. md5")
        print("2. sha1")
        print("3. sha224")
        print("4. sha256")
        print("5. sha384")
        print("6. sha512")
        algorithm = input("请输入选择的哈希算法数字：")
        if algorithm in ['1', '2', '3', '4', '5', '6']:
            algorithm = {
                '1': 'md5',
                '2': 'sha1',
                '3': 'sha224',
                '4': 'sha256',
                '5': 'sha384',
                '6': 'sha512'
            }[algorithm]
            num_messages = int(input("请输入要生成的消息数量："))
            messages = []
            for i in range(num_messages):
                message = input(f"请输入第 {i + 1} 条消息：")
                messages.append(message)

            generate_dictionary(messages, algorithm)
            print("消息-哈希值对已保存到 result.txt 文件。")

            # 判断用户是否继续输入
            choice = input("是否继续输入消息和生成字典？(y/n): ")
            if choice.lower() != 'y':
                break
        else:
            print("输入无效，请重新输入。")

def hash_cracker_menu():
    flag = 1
    while flag:
        try:
            hashed = input('\n请输入将要爆破的哈希值：\nPlease input the hash code:')
            hashed = hashed.lower()
            length = len(hashed)
            if length not in [32, 40, 56, 64, 96, 128]:
                print('\n无效哈希值\nThe hash value is unavailible.\n')
                continue
            flag = 0
        except Exception as e:
            print(e)

    method = judge(length)

    while True:
        try:
            print('1.纯字符	2.自定义字符	3.字典')
            option = int(input('\n请选择爆破方式：\nPlease select the option:'))
            if option not in [1, 2, 3]:
                print('\n输入不在选项内\n')
                continue
            break
        except:
            print('\n输入不在选项内\n')

    if option == 1:
        print('\n选择的爆破方式为 纯数字爆破\n')
        chars_break(method, hashed)
    elif option == 2:
        print('\n选择的爆破方式为 自定义字符\n')
        self_define(method, hashed)
    elif option == 3:
        print('\n选择的爆破方式为 字典爆破\n')
        dic_break(method, hashed)

    os.system('pause')

# 修改 judge 函数，直接返回哈希算法的名称
def judge(length):
    if length == 32:
        return 'md5'
    elif length == 40:
        return 'sha1'
    elif length == 56:
        return 'sha224'
    elif length == 64:
        return 'sha256'
    elif length == 96:
        return 'sha384'
    elif length == 128:
        return 'sha512'
    else:
        raise ValueError("Invalid hash length")

#设置明文长度
def set_length():
    min = max = 0
    print('\n请分别设置明文最小最大长度，可设置两者大小相同\n')
    print('Please set the min and max length.They could be the same.\n')
    while 1:
        while 1:
            try:
                min = int(input('\n请输入明文的最短长度：\nPlease input the min length:'))
                break
            except:
                print('\n输入内容不符\n')
        while 1:
            try:
                max = int(input('\n请输入明文的最长长度：\nPlease input the max length:'))
                break
            except:
                print('\n输入内容不符\n')
        if min > max:
            print('\n最短长度大于最长长度，重新输入\nTry again\n')
            continue
        else:
            return min, max

#提取包含字符，去重
def cancel_repeat(origin):
    origin_list = list(origin)
    char_ = []
    for i in origin_list:
        if i not in char_:
            char_.append(i)
    char = ''.join(char_)
    return char

#自定义字符爆破
def self_define(method, hashed):
    origin = input('请输入需要包含的明文字符：')
    chars = cancel_repeat(origin)
    min, max = set_length()

    #开始进行字符串爆破
    start_break(method, hashed, min, max, chars)

## 打开文件以进行写入操作
result_file = open("result.txt", "a+")

# 进行哈希计算
def calculate(plain, method):
    if method == 'md5':
        ha_ = hashlib.md5()
    elif method == 'sha1':
        ha_ = hashlib.sha1()
    elif method == 'sha224':
        ha_ = hashlib.sha224()
    elif method == 'sha256':
        ha_ = hashlib.sha256()
    elif method == 'sha384':
        ha_ = hashlib.sha384()
    elif method == 'sha512':
        ha_ = hashlib.sha512()
    else:
        raise ValueError("Invalid hash algorithm")

    ha_.update(plain.encode("utf-8"))    # Unicode-objects must be encoded before hashing
    return ha_.hexdigest()

# 开始进行爆破
def start_break(method, hashed, min_length=0, max_length=0, chars=None, dic=None):
    found = False  # 用于标记是否找到匹配的明文字符串
    if dic is None:
        for length in range(min_length, max_length + 1):
            for one in itertools.product(chars, repeat=length):
                one = ''.join(one)
                hashed_ = calculate(one, method)
                if hashed_ == hashed:
                    print("找到匹配的明文字符串:")
                    print(f"哈希值: {hashed}")
                    print(f"明文字符串: {one}")
                    result_file.write(f"{hashed_} : {one}\n")  # 将结果写入文件
                    result_file.flush()  # 立即刷新缓冲区，确保写入文件
                    found = True  # 找到结果后将标记置为True
                    break  # 找到结果后立即退出内层循环
            if found:  # 如果找到结果，直接退出外层循环
                break
    elif dic is not None:
        for single in dic:
            cut = single.strip()  # 去除字符串两端的空白字符，包括换行符
            hashed_ = calculate(cut, method)
            if hashed_ == hashed:
                print("找到匹配的明文字符串:")
                print(f"哈希值: {hashed}")
                print(f"明文字符串: {cut}")
                result_file.write(f"{hashed_} : {cut}\n")  # 将结果写入文件
                result_file.flush()  # 立即刷新缓冲区，确保写入文件
                found = True  # 找到结果后将标记置为True
                break  # 找到结果后立即退出循环

    if not found:  # 如果未找到结果，则输出相应信息
        print("未找到匹配的明文字符串.")  # 输出未找到匹配的明文字符串信息


# 纯字符爆破
def chars_break(method, hashed):
    min_length, max_length = set_length()

    options = input(
        '\n请选择要使用的字符集合：\n1. 数字\n2. 大写字母\n3. 小写字母\n4. 特殊字符\n请选择（例如选择1234表示使用数字、大写字母、小写字母和特殊字符）：')
    while not all(option.isdigit() and 1 <= int(option) <= 4 for option in options):
        print("请输入有效选项。")
        options = input(
            '\n请选择要使用的字符集合：\n1. 数字\n2. 大写字母\n3. 小写字母\n4. 特殊字符\n请选择（例如选择1234表示使用数字、大写字母、小写字母和特殊字符）：')

    chars = ''
    if '1' in options:
        chars += '0123456789'
    if '2' in options:
        chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if '3' in options:
        chars += 'abcdefghijklmnopqrstuvwxyz'
    if '4' in options:
        chars += '!@#$%^&*()_+-=[]\\{}|;\':",./<>? '

    for length in range(min_length, max_length + 1):
        for combination in itertools.product(chars, repeat=length):
            combination_str = ''.join(combination)
            hashed_ = calculate(combination_str, method)
            if hashed_ == hashed:
                print("找到匹配的明文字符串:")
                print(f"哈希值: {hashed}")
                print(f"明文字符串: {combination_str}")
                result_file.write(f"{hashed_} : {combination_str}\n")  # 将结果写入文件
                result_file.flush()  # 立即刷新缓冲区，确保写入文件
                return True  # 找到结果后立即返回True

    print("未找到匹配的明文字符串。")
    return False  # 未找到结果返回False

def dic_break(algorithm, hashed):
    # 选择使用默认字典还是自定义字典
    while True:
        print("请选择字典来源：")
        print("1. 默认字典")
        print("2. 自定义字典")
        source_option = input("请选择（输入1或2）：")
        if source_option == '1':
            # 使用默认字典
            dic_filename = f"hashdics/sorted_{algorithm}_dic.txt"
            break
        elif source_option == '2':
            # 使用自定义字典
            dic_filename = input("请输入自定义字典文件路径：")
            break
        else:
            print("输入无效，请重新输入。")

    try:
        # 打开字典文件
        with open(dic_filename, 'r') as f:
            print("字典文件打开成功！")

            # 初始化分块读取参数
            block_size = 4096  # 每次读取的块大小
            lines = []  # 存储当前块内的行数据
            position = 0  # 记录当前文件指针位置

            # 分块读取文件
            while True:
                chunk = f.read(block_size)
                if not chunk:
                    break  # 文件读取结束

                lines.extend(chunk.splitlines())  # 将读取的内容按行分割并添加到 lines 中

                # 查找是否有完整的行
                while lines[-1] != '\n':
                    chunk = f.read(block_size)
                    if not chunk:
                        break  # 文件读取结束
                    lines.extend(chunk.splitlines())  # 将读取的内容按行分割并添加到 lines 中

                # 处理当前块内的行数据
                sorted_hashes = sorted(line.split(':')[0].strip()[:5] for line in lines)

                # 使用二分搜索查找匹配的哈希值
                left, right = 0, len(sorted_hashes) - 1
                while left <= right:
                    mid = (left + right) // 2
                    if sorted_hashes[mid] == hashed[:5]:
                        # 找到匹配的前五位哈希值，继续在字典中查找完整的哈希值
                        for line in lines:
                            pair = line.strip().split(':')
                            if len(pair) == 2:
                                hashed_message, message = pair[0].strip(), pair[1].strip()
                                if hashed_message == hashed:
                                    print('\nFOUND:', message, '\n')  # 输出找到的结果
                                    result_file.write(f"{hashed_message} : {message}\n")  # 将结果写入文件
                                    result_file.flush()  # 立即刷新缓冲区，确保写入文件
                                    return True
                        break  # 如果哈希表的前五位有序但未找到匹配的哈希值，无需继续搜索
                    elif sorted_hashes[mid] < hashed[:5]:
                        left = mid + 1
                    else:
                        right = mid - 1

                # 重置 lines，准备读取下一块数据
                lines = [lines[-1]]

                # 更新文件指针位置
                position = f.tell()
                f.seek(position)

    except FileNotFoundError:
        print("字典文件不存在或路径无效！")
        return False

    print('\n无结果\n404: Not Found\n')
    return False

def read_file_in_chunks(file_path, chunk_size=1024):
    with open(file_path, 'r') as file:
        while True:
            data = file.read(chunk_size)
            if not data:
                break
            yield data

if __name__ == '__main__':
    main()


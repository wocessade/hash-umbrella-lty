import tkinter as tk
import hashlib
import itertools
import string
import threading
import time
from PIL import Image, ImageTk
from tkinter import filedialog, messagebox, StringVar
result_file = open("result.txt", "a+")
    
def clear_widgets():
    # 遍历主窗口中的所有部件
    for widget in root.winfo_children():
        # 检查部件是否是菜单栏的子部件
        if widget != menubar and widget.winfo_ismapped():
            widget.destroy()

def blink_rotate(image_label, original_image):
    for i in range(1):
        for _ in range(1):  # 控制闪烁的次数
            image_label.config(image="")
            root.update()
            time.sleep(0.2)
            image_label.config(image=photo)
            root.update()
            time.sleep(0.2)
        for _ in range(360):  # 控制旋转的角度
            rotated_image = original_image.rotate(_)
            rotated_photo = ImageTk.PhotoImage(rotated_image)
            image_label.config(image=rotated_photo)
            image_label.image = rotated_photo
            root.update()
        time.sleep(0.2)

def generate_hash(message, algorithm):
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

def judge( chars, hashed, min_length, max_length):
    length = len(hashed)
    if min_length == '':
        min_length = 1
    if max_length == '':
        max_length = 1
    try:
        max_length = int(max_length)
        min_length = int(min_length)
    except ValueError:
        return False,f"最短长度\最长长度有误！",""
    if min_length > max_length or min_length <=0 or max_length <=0:
        return False,f"最短长度\最长长度有误！",""
    elif chars == '':
        return False,f"未选择可能出现的字符！",""
    elif length == 32:
        return True,f"",'md5'
    elif length == 40:
        return True,f"",'sha1'
    elif length == 56:
        return True,f"",'sha224'
    elif length == 64:
        return True,f"",'sha256'
    elif length == 96:
        return True,f"",'sha384'
    elif length == 128:
        return True,f"",'sha512'
    else:
        return False,f"非法哈希值",""

def decryption_menu3(root):
    clear_widgets()
    tk.Label(root, text="哈希破解工具\n\n字典爆破\n\n选择字典:").pack(pady=1)
    # 切换可用性
    def toggle_visibility(radio_button):
        if radio_button == show_button:
            entry.config(state='normal')
            select_file_button.config(state='normal') 
        else:
            entry.config(state='disabled')
            select_file_button.config(state='disabled') 
    # 创建两个单选按钮
    show_var = tk.StringVar(value='默认字典')
    hide_button = tk.Radiobutton(root, text="默认字典", variable=show_var, value='默认字典', command=lambda: toggle_visibility(hide_button))
    show_button = tk.Radiobutton(root, text="自定义字典", variable=show_var, value='自定义字典', command=lambda: toggle_visibility(show_button))
    hide_button.pack(pady=1)
    show_button.pack(pady=1)
    # 创建自定义字典的文本框
    # 创建用于存储文件路径的StringVar
    file_path_var = StringVar()
    # 创建标签来显示当前选择的文件/文件夹路径
    file_path_label = tk.Label(root, textvariable=file_path_var,fg="green")
    file_path_label.pack(pady=10)
    # 创建函数来选择文件并更新标签
    def select_file():
        global selected_file_path
        selected_file_path = filedialog.askopenfilename()
        if selected_file_path:
            entry.delete(0, tk.END)
            entry.insert(0, selected_file_path)
        else:
            messagebox.showinfo("提示", "未选择文件！")
    def on_entry_focus(event):
        if entry.get() == placeholder_text:
            entry.delete(0, tk.END)
            entry.config(fg='black')  
    def on_entry_blur(event):
        if not entry.get():
            entry.insert(0, placeholder_text)
            entry.config(fg='gray')
    placeholder_text = "自定义字典路径"
    entry = tk.Entry(root, textvariable=file_path_var,fg='gray',width=30)
    entry.insert(0, placeholder_text)
    entry.bind("<FocusIn>", on_entry_focus)
    entry.bind("<FocusOut>", on_entry_blur)
    entry.config(state='disabled')
    entry.pack(pady=5)
    # 创建按钮来选择文件
    select_file_button = tk.Button(root, text="浏览...", command=select_file)
    select_file_button.config(state='disabled')
    select_file_button.pack(pady=5)
    tk.Label(root, text="明文最短长度(默认:1)").pack(pady=1)
    message_entry2 = tk.Entry(root, width= 5)
    message_entry2.pack(pady=5)
    tk.Label(root, text="明文最长长度(默认:1)").pack(pady=1)
    message_entry3 = tk.Entry(root, width= 5)
    message_entry3.pack(pady=5)
    #待破解消息输入框
    tk.Label(root, text="待破解消息").pack(pady=1)
    message_entry4 = tk.Entry(root, width= 50)
    message_entry4.pack(pady=5)
    result_label = tk.Label(root, text="")
    result_label.pack(pady=1)
    def update_label():
        result_label.config(text="正在破解——", fg="green")
    def on_button_click():
        update_label()
        threading.Thread(target=dic_break, args=(message_entry4.get(), message_entry2.get(), message_entry3.get(), show_var.get(), entry.get())).start()
    #加密按钮
    button = tk.Button(root, text="开始破解",command=lambda:on_button_click())
    button.pack()
    def dic_break(hashed,min_length,max_length,source_option,self_defined):
        is_valid, message, algorithm = judge( source_option, hashed, min_length, max_length)
        # 选择使用默认字典还是自定义字典
        if is_valid:
            if min_length == '':
                min_length = 1
            if max_length == '':
                max_length = 1
            max_length = int(max_length)
            min_length = int(min_length)
            if source_option == '默认字典':
                dic_filename = f"hashdics/sorted_{algorithm}_dic.txt"
            elif source_option == '自定义字典':
                dic_filename = self_defined
                # 检查文件名是否以 .txt 结尾
                if not self_defined.lower().endswith('.txt'):
                    result_label.config(text="警告：自定义字典文件必须是 .txt 格式", fg="red")
                dic_filename = self_defined
            try:
                found = False  # 用于标记是否找到匹配的明文字符串
                with open(dic_filename, 'r') as f:
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
                                            result_label.config(text= f"找到匹配的明文字符串:{message}\n\n加密算法:{algorithm}\n\n结果已存入'result.txt'",fg="green")
                                            result_file.write(f"{hashed_message} : {message}\n")  # 将结果写入文件
                                            result_file.flush()  # 立即刷新缓冲区，确保写入文件
                                            found = True  # 找到结果后将标记置为True
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
                result_label.config(text= "文件路径错误！",fg="red")
            if not found:  # 如果未找到结果，则输出相应信息
                result_label.config(text=f"未找到匹配的明文字符串\n\n加密算法:{algorithm}",fg="red")
        else:
            result_label.config(text= message,fg="red")
            
#自定义爆破界面
def decryption_menu2(root):
    clear_widgets()
    tk.Label(root, text="哈希破解工具\n\n自定义爆破\n\n输入明文中可能出现的字符:").pack(pady=1)
    message_entry1 = tk.Entry(root)
    message_entry1.pack(pady=5)
    #提取包含字符，去重
    def cancel_repeat(origin):
        origin_list = list(origin)
        char_ = []
        for i in origin_list:
            if i not in char_:
                char_.append(i)
        char = ''.join(char_)
        return char
    tk.Label(root, text="明文最短长度(默认:1)").pack(pady=1)
    message_entry2 = tk.Entry(root, width= 5)
    message_entry2.pack(pady=5)
    tk.Label(root, text="明文最长长度(默认:1)").pack(pady=1)
    message_entry3 = tk.Entry(root, width= 5)
    message_entry3.pack(pady=5)
    #待破解消息输入框
    tk.Label(root, text="待破解消息").pack(pady=1)
    message_entry4 = tk.Entry(root, width= 50)
    message_entry4.pack(pady=5)
    def update_label():
        result_label.config(text="正在破解——", fg="green")
    def on_button_click():
        update_label()
        threading.Thread(target=self_defined, args=(message_entry4.get(),message_entry2.get(),message_entry3.get(),cancel_repeat(message_entry1.get()))).start()
    #加密按钮
    button = tk.Button(root, text="开始破解", command=lambda: on_button_click())
    button.pack()
    result_label = tk.Label(root, text="")
    result_label.pack(pady=5)
    def self_defined(hashed, min_length, max_length, chars):
        is_valid, message, method = judge( chars, hashed, min_length, max_length)
        if is_valid:
            if min_length == '':
                min_length = 1
            if max_length == '':
                max_length = 1
            max_length = int(max_length)
            min_length = int(min_length)
            found = False  # 用于标记是否找到匹配的明文字符串
            for length in range(min_length, max_length + 1):
                for one in itertools.product(chars, repeat=length):
                    one = ''.join(one)
                    hashed_ = generate_hash(one, method)
                    if hashed_ == hashed:
                        result_label.config(text=f"明文字符串:{one}\n\n加密算法:{method}\n\n结果已存入'result.txt'",fg="green")
                        result_file.write(f"{hashed_} : {one}\n")  # 将结果写入文件
                        result_file.flush()  # 立即刷新缓冲区，确保写入文件
                        found = True  # 找到结果后将标记置为True
                        break  # 找到结果后立即退出内层循环
                if found:  # 如果找到结果，直接退出外层循环
                    break
            if not found:  # 如果未找到结果，则输出相应信息
                result_label.config(text=f"未找到匹配的明文字符串\n\n加密算法:{method}",fg="red")
        else:
            result_label.config(text= message,fg="red")

#暴力破解界面
def decryption_menu1(root):
    clear_widgets()
    tk.Label(root, text="哈希破解工具\n\n暴力破解\n\n选择明文中可能出现的字符类型:").pack(pady=1)
    # 创建一个字典来存储复选框的状态
    checkbox_states = {'数      字': False, '大写字母': False, '小写字母': False, '特殊符号': False}
    # 创建复选框变量
    var1 = tk.IntVar()
    var2 = tk.IntVar()
    var3 = tk.IntVar()
    var4 = tk.IntVar()
    # 将复选框变量的值与字典中的初始状态关联起来
    var1.set(checkbox_states['数      字'])
    var2.set(checkbox_states['大写字母'])
    var3.set(checkbox_states['小写字母'])
    var4.set(checkbox_states['特殊符号'])
    # 定义回调函数，当复选框状态改变时更新字典
    def update_checkbox_states(*args):
        checkbox_states['数      字'] = var1.get()
        checkbox_states['大写字母'] = var2.get()
        checkbox_states['小写字母'] = var3.get()
        checkbox_states['特殊符号'] = var4.get()
        chars = ''
        if checkbox_states['数      字']:
            chars += '0123456789'
        if checkbox_states['大写字母']:
            chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        if checkbox_states['小写字母']:
            chars += 'abcdefghijklmnopqrstuvwxyz'
        if checkbox_states['特殊符号']:
            chars += '!@#$%^&*()_+-=[]\\{}|;\':",./<>? '
        if chars == '':
            return ''
        return chars
    
    def char_crack(chars,hashed,min_length, max_length):
        is_valid,message,method = judge( chars, hashed, min_length, max_length)
        if is_valid:
            if min_length == '':
                min_length = 1
            if max_length == '':
                max_length = 1
            max_length = int(max_length)
            min_length = int(min_length)
            found = False  # 用于标记是否找到匹配的明文字符串
            for length in range(min_length, max_length + 1):
                for combination in itertools.product(chars, repeat=length):
                    combination_str = ''.join(combination)
                    hashed_ = generate_hash(combination_str, method)
                    if hashed_ == hashed:
                        result_label.config(text=f"明文字符串:{combination_str}\n\n加密算法:{method}\n\n结果已存入'result.txt'",fg="green")
                        result_file.write(f"{hashed_} : {combination_str}\n")  # 将结果写入文件
                        result_file.flush()  # 立即刷新缓冲区，确保写入文件
                        found = True  # 找到结果后将标记置为True
                        break
                if found:  # 如果找到结果，直接退出外层循环
                    break
            if not found:  # 如果未找到结果，则输出相应信息
                result_label.config(text=f"未找到匹配的明文字符串\n\n加密算法:{method}",fg="red")
        else:
            result_label.config(text= message,fg="red")
    # 创建复选框并使用grid方法将它们放在同一行
    checkbutton1 = tk.Checkbutton(root, text="数      字", variable=var1)
    checkbutton1.pack()
    checkbutton2 = tk.Checkbutton(root, text="大写字母", variable=var2)
    checkbutton2.pack()
    checkbutton3 = tk.Checkbutton(root, text="小写字母", variable=var3)
    checkbutton3.pack()
    checkbutton4 = tk.Checkbutton(root, text="特殊符号", variable=var4)
    checkbutton4.pack()
    # 将更新函数绑定到每个复选框的trace方法上
    var1.trace("w", update_checkbox_states)
    var2.trace("w", update_checkbox_states)
    var3.trace("w", update_checkbox_states)
    var4.trace("w", update_checkbox_states)
    tk.Label(root, text="明文最短长度(默认:1)").pack(pady=1)
    message_entry1 = tk.Entry(root, width= 5)
    message_entry1.pack(pady=5)
    tk.Label(root, text="明文最长长度(默认:1)").pack(pady=1)
    message_entry2 = tk.Entry(root, width= 5)
    message_entry2.pack(pady=5)
    tk.Label(root, text="待破解消息").pack(pady=1)
    message_entry3 = tk.Entry(root, width= 50)
    message_entry3.pack(pady=5)
    def update_label():
        result_label.config(text="正在破解——", fg="green")
    def on_button_click():
        update_label()
        threading.Thread(target=char_crack, args=(update_checkbox_states(),message_entry3.get(),message_entry1.get(), message_entry2.get())).start()
    button1 = tk.Button(root, text="开始破解", command=lambda:on_button_click())
    button1.pack()
    result_label = tk.Label(root, text="",fg="green")
    result_label.pack(pady=5)

#字典生成界面
def dicgen_menu(root):
    clear_widgets()
    def generate_rainbow_table(algorithm, min_length, max_length, preprocess=True, prefix_length=None):
        is_valid, message, a= judge( '0', [0]*32 , min_length, max_length)
        if is_valid:
            if min_length == '':
                min_length = 1
            if max_length == '':
                max_length = 1
            max_length = int(max_length)
            min_length = int(min_length)
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
            filename = f"sorted_{var.get()}_dic.txt"
            save_rainbow_table(rainbow_table, filename)
        else:
            result_label.config(text= message,fg="red")
    
    def hash_text(text, algorithm):
        hash_object = hashlib.new(algorithm)
        hash_object.update(text.encode('utf-8'))
        return hash_object.hexdigest()
    
    def save_rainbow_table(table, filename):
        with open(filename, 'w') as file:
            for hashed, word in table.items():
                file.write(f"{hashed}:{word}\n")
            result_label.config(text = f"生成成功！\n字典已保存到 {filename} 文件中。")
                
    tk.Label(text="字典生成器\n\n选择算法\n").pack()
    algorithms_frame = tk.Frame(root)
    algorithms_frame.pack(pady=5)
    algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    var = tk.StringVar(value=algorithms[0])
    for algorithm in algorithms:
        rb = tk.Radiobutton(algorithms_frame, text=algorithm, variable=var, value=algorithm.lower())
        rb.pack(side=tk.LEFT, padx=5)

    tk.Label(root, text="明文最短长度(默认:1)").pack(pady=1)
    message_entry1 = tk.Entry(root, width= 5)
    message_entry1.pack(pady=5)
    tk.Label(root, text="明文最长长度(默认:1)").pack(pady=1)
    message_entry2 = tk.Entry(root, width= 5)
    message_entry2.pack(pady=5)
    def update_label():
        result_label.config(text="正在生成——", fg="green")
    def on_button_click():
        update_label()
        threading.Thread(target=generate_rainbow_table, args=(var.get(), message_entry1.get(), message_entry2.get())).start()
        blink_rotate(image_label, original_image)
    #加密按钮
    button = tk.Button(root, text="生成字典", command=lambda: on_button_click())
    button.pack(pady=20)
    result_label = tk.Label(root, text="",fg="green")
    result_label.pack(pady=20)
    image_label = tk.Label(root, image=photo)
    image_label.pack(side=tk.LEFT)
    blink_rotate(image_label, original_image)

#加密工具界面
def encryption_menu(root):
    clear_widgets()
    def generate_dictionary(message, algorithm):
        with open("result.txt", 'a+') as file:  # 修改为追加模式
            hash_value = generate_hash(message, algorithm)
            file.write(f"{hash_value} : {message}\n")  # 将哈希值放在前面
    def generate_hash_value(algorithm, message):
        hash_value = generate_hash(message, algorithm)
        result_label.config(text=f"哈希值: {hash_value}\n\n结果已存入'result.txt'")
        generate_dictionary(message, algorithm)
    tk.Label(root, text="哈希加密工具\n\n选择算法\n").pack(pady=20)
    #算法选择按钮组件
    algorithms_frame = tk.Frame(root)
    algorithms_frame.pack(pady=5)
    algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    var = tk.StringVar(value=algorithms[0])
    for algorithm in algorithms:
        rb = tk.Radiobutton(algorithms_frame, text=algorithm, variable=var, value=algorithm.lower())
        rb.pack(side=tk.LEFT, padx=5)
    #待加密消息输入框
    message_entry = tk.Entry(root)
    message_entry.pack(pady=10)
    #加密按钮
    hash_button = tk.Button(root, text="生成哈希", command=lambda: (generate_hash_value(var.get(), message_entry.get()),blink_rotate(image_label, original_image)))
    hash_button.pack(pady=10)
    #密文输出
    result_label = tk.Label(root, text="",fg="green")
    result_label.pack(pady=10)
    image_label = tk.Label(root, image=photo)
    image_label.pack(side=tk.LEFT)
    blink_rotate(image_label, original_image)

def filehash_menu(root):
    clear_widgets()
    def select_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            file_entry.delete(0, tk.END)
            file_entry.insert(tk.END, file_path)

    def calculate_hash():
        file_path = file_entry.get()
        if file_path:
            hash_algorithm = hash_algorithm_var.get().lower()
            if hash_algorithm in hashlib.algorithms_guaranteed:
                hash_obj = hashlib.new(hash_algorithm)
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_obj.update(chunk)
                file_hash = hash_obj.hexdigest()
                hash_text.delete("1.0", tk.END)
                hash_text.insert(tk.END, file_hash)
                result_label.config(text="计算完成！",fg = "green")
            else:
                hash_text.delete("1.0", tk.END)
                hash_text.insert(tk.END, "无效的哈希算法")
                result_label.config(text="无效的哈希算法！",fg = "red")
        else:
            hash_text.delete("1.0", tk.END)
            hash_text.insert(tk.END, "请先选择一个文件")
            result_label.config(text="请先选择一个文件！",fg = "red")

    def check_hash():
        file_path = file_entry.get()
        if file_path:
            input_hash = input_entry.get()
            if input_hash:
                hash_algorithm = hash_algorithm_var.get().lower()
                if hash_algorithm in hashlib.algorithms_guaranteed:
                    hash_obj = hashlib.new(hash_algorithm)
                    with open(file_path, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hash_obj.update(chunk)
                    file_hash = hash_obj.hexdigest()
                    if file_hash == input_hash:
                        result_label.config(text="哈希值匹配！",fg = "green")
                    else:
                        result_label.config(text="哈希值不匹配！",fg = "red")
            else:
                result_label.config(text="请输入要校验的哈希值！",fg = "red")
        else:
            
            result_label.config(text="请先选择一个文件！",fg = "red")

    tk.Label(root, text="文件校验工具\n\n选择算法").pack(pady=20)
    # 哈希算法选择部分
    algorithms_frame = tk.Frame(root)
    algorithms_frame.pack(pady=5)

    algorithms = ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']
    hash_algorithm_var = tk.StringVar(value=algorithms[0])

    for algorithm in algorithms:
        rb = tk.Radiobutton(algorithms_frame, text=algorithm, variable=hash_algorithm_var, value=algorithm)
        rb.pack(side=tk.LEFT, padx=5)

    # 文件选择部分
    file_frame = tk.Frame(root)
    file_frame.pack(pady=5)
    file_label = tk.Label(file_frame, text="选择一个文件:")
    file_label.pack(pady=5)
    file_entry = tk.Entry(file_frame, width=40)
    file_entry.pack(pady=5)
    file_button = tk.Button(file_frame, text="浏览", command=select_file)
    file_button.pack(pady=5)
    # 显示哈希值部分
    hash_frame = tk.Frame(root)
    hash_frame.pack(pady=5)
    hash_label = tk.Label(hash_frame, text="文件哈希值结果:")
    hash_label.pack(side=tk.LEFT)
    hash_text = tk.Text(hash_frame, height=1, width=40)
    hash_text.pack(side=tk.LEFT, padx=5)
    # 输入哈希值部分
    input_frame = tk.Frame(root)
    input_frame.pack(pady=5)
    input_label = tk.Label(input_frame, text="输入校验哈希值:")
    input_label.pack(side=tk.LEFT)
    input_entry = tk.Entry(input_frame, width=40)
    input_entry.pack(side=tk.LEFT, padx=5)
    # 计算哈希值按钮
    calc_button = tk.Button(root, text="计算哈希值", command=lambda:(calculate_hash(),blink_rotate(image_label, original_image)))
    calc_button.pack(pady=5)
    # 校验哈希值按钮
    check_button = tk.Button(root, text="校验哈希值", command=lambda:(check_hash(),blink_rotate(image_label, original_image)))
    check_button.pack(pady=5)
    result_label = tk.Label(text = "", fg ="green")
    result_label.pack()
    image_label = tk.Label(root, image=photo)
    image_label.pack(side=tk.LEFT)
    blink_rotate(image_label, original_image)

# 创建主窗口
root = tk.Tk()
root.title("哈希小工具")
root.geometry("950x550")  # 调整窗口大小以适应内容
# 创建菜单栏
menubar = tk.Menu(root)
# 创建加密哈希子菜单
encrypt_menu = tk.Menu(menubar, tearoff=0)
encrypt_menu.add_command(label="算法加密", command=lambda: encryption_menu(root))
encrypt_menu.add_command(label="生成字典",command=lambda:dicgen_menu(root))
# 创建破解哈希子菜单
crack_menu = tk.Menu(menubar, tearoff=0)
crack_menu.add_command(label="暴力破解", command=lambda: decryption_menu1(root))
crack_menu.add_command(label="自定义爆破", command=lambda: decryption_menu2(root))
crack_menu.add_command(label="字典爆破", command=lambda: decryption_menu3(root))
# 将子菜单添加到菜单栏
menubar.add_cascade(label="哈希加密工具", menu=encrypt_menu)
menubar.add_cascade(label="哈希破解工具", menu=crack_menu)
menubar.add_cascade(label="文件校验工具", command=lambda: filehash_menu(root))
# 将菜单栏添加到主窗口
root.config(menu=menubar)
tk.Label(text="欢迎使用哈希小工具",fg = "red",font=30).pack(pady=10)
# 加载图像
image_path = "lq.jpg"
original_image = Image.open(image_path)
photo = ImageTk.PhotoImage(original_image)
# 显示图像
image_label = tk.Label(root, image=photo)
image_label.pack()
blink_rotate(image_label, original_image)
# 运行主循环
root.mainloop()
# 开始闪烁并旋转
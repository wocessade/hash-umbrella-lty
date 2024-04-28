import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

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
        else:
            hash_text.delete("1.0", tk.END)
            hash_text.insert(tk.END, "无效的哈希算法。")
    else:
        hash_text.delete("1.0", tk.END)
        hash_text.insert(tk.END, "请先选择一个文件。")

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
                    messagebox.showinfo("结果", "哈希值匹配！")
                else:
                    messagebox.showerror("结果", "哈希值不匹配！")
            else:
                messagebox.showerror("错误", "无效的哈希算法。")
        else:
            messagebox.showwarning("警告", "请输入要校验的哈希值。")
    else:
        messagebox.showwarning("警告", "请先选择一个文件。")

# 创建主窗口
root = tk.Tk()
root.title("文件哈希校验器")

# 文件选择部分
file_frame = tk.Frame(root)
file_frame.pack(pady=5)

file_label = tk.Label(file_frame, text="选择一个文件:")
file_label.pack(side=tk.LEFT)

file_entry = tk.Entry(file_frame, width=40)
file_entry.pack(side=tk.LEFT, padx=5)

file_button = tk.Button(file_frame, text="浏览", command=select_file)
file_button.pack(side=tk.LEFT)

# 哈希算法选择部分
algorithms_frame = tk.Frame(root)
algorithms_frame.pack(pady=5)

algorithms = ['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512']
hash_algorithm_var = tk.StringVar(value=algorithms[0])

for algorithm in algorithms:
    rb = tk.Radiobutton(algorithms_frame, text=algorithm, variable=hash_algorithm_var, value=algorithm)
    rb.pack(side=tk.LEFT, padx=5)

# 显示哈希值部分
hash_frame = tk.Frame(root)
hash_frame.pack(pady=5)

hash_label = tk.Label(hash_frame, text="哈希值:")
hash_label.pack(side=tk.LEFT)

hash_text = tk.Text(hash_frame, height=1, width=40)
hash_text.pack(side=tk.LEFT, padx=5)

# 输入哈希值部分
input_frame = tk.Frame(root)
input_frame.pack(pady=5)

input_label = tk.Label(input_frame, text="输入哈希值:")
input_label.pack(side=tk.LEFT)

input_entry = tk.Entry(input_frame, width=40)
input_entry.pack(side=tk.LEFT, padx=5)

# 计算哈希值按钮
calc_button = tk.Button(root, text="计算哈希值", command=calculate_hash)
calc_button.pack(pady=5)

# 校验哈希值按钮
check_button = tk.Button(root, text="校验哈希值", command=check_hash)
check_button.pack(pady=5)

# 运行主循环
root.mainloop()

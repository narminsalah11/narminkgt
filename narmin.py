import tkinter as tk
from tkinter import ttk
from tkinter.messagebox import showinfo
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import pyperclip
from hashlib import sha256
from PIL import Image, ImageTk


# إظهار أو إخفاء كلمة المرور
def toggle_password_visibility():
    global password_visible
    if password_visible:
        password_input.config(show="*")
        toggle_button.config(image=eye_closed_image)
    else:
        password_input.config(show="")
        toggle_button.config(image=eye_open_image)
    password_visible = not password_visible


def generate_key(password):
    return sha256(password.encode()).digest()


# خوارزمية قيصر المعدلة
def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    result = []
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
        else:
            result.append(char)
    return ''.join(result)

# تشفير النص
def encrypt_message():
    algorithm = selected_algorithm.get()
    password = password_input.get()
    message = text2.get("1.0", tk.END).strip()

    if not password or not message:
        showinfo("Error", "الرجاء إدخال كلمة المرور.")
        return

    if algorithm == "Caesar Cipher":
        if not password.isdigit():
            showinfo("Error", "الرجاء إدخال كلمة مرور رقمية لخوارزمية قيصر.")
            return
        shift = int(password) % 26  # تحويل كلمة المرور إلى قيمة shift
        encrypted_message = caesar_cipher(message, shift)

    elif algorithm == "AES":
        if not password:
            showinfo("Error", "الرجاء إدخال كلمة المرور.")
            return
        key = generate_key(password)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_message = encrypted_message.hex()

    else:
        showinfo("Error", "يرجى اختيار خوارزمية.")
        return

    text1.delete("1.0", tk.END)
    text1.insert(tk.END, encrypted_message)


# فك تشفير النص
def decrypt_message():
    algorithm = selected_algorithm.get()
    password = password_input.get()
    encrypted_message = text2.get("1.0", tk.END).strip()

    if not encrypted_message:
        showinfo("Error", "الرجاء إدخال النص المشفر.")
        return

    if algorithm == "Caesar Cipher":
        if not password.isdigit():
            showinfo("Error", "الرجاء إدخال كلمة مرور رقمية لخوارزمية قيصر.")
            return
        shift = int(password) % 26
        decrypted_message = caesar_cipher(encrypted_message, shift, decrypt=True)

    elif algorithm == "AES":
        if not password:
            showinfo("Error", "الرجاء إدخال كلمة المرور.")
            return
        try:
            encrypted_message_bytes = bytes.fromhex(encrypted_message)
            iv = encrypted_message_bytes[:16]
            encrypted_message = encrypted_message_bytes[16:]
            key = generate_key(password)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
            decrypted_message = decrypted_message.decode()
        except Exception as e:
            showinfo("Error", f"فشل فك التشفير: {e}")
            return
    else:
        showinfo("Error", "يرجى اختيار خوارزمية.")
        return

    text1.delete("1.0", tk.END)
    text1.insert(tk.END, decrypted_message)


def copy_encrypted_message():
    encrypted_message = text1.get("1.0", tk.END).strip()
    if encrypted_message:
        pyperclip.copy(encrypted_message)
        showinfo("Success", "تم نسخ النص بنجاح")


# إعداد الواجهة الرسومية
root = tk.Tk()
root.title("تشفير الرسائل")
root.geometry("900x600")
root.configure(bg="#b8b0d2")
root.iconbitmap('C:\\Users\\HP-PC\\Desktop\\data1.ico')

# قائمة لاختيار الخوارزمية
selected_algorithm = tk.StringVar(value="Caesar Cipher")

ttk.Label(root, text=": اختر خوارزمية ", font=("Helvetica", 18), foreground="black", background="#b8b0d2").grid(row=0, column=1, padx=20,
                                                                                          pady=100, sticky="N")
algorithm_menu = ttk.Combobox(root, textvariable=selected_algorithm, values=["Caesar Cipher", "AES"], state="readonly",
                              width=20)
algorithm_menu.grid(row=0, column=1, padx=20, pady=150 , sticky="n")

style = ttk.Style()
style.configure("TLabel", foreground="white",  font=("Helvetica", 12))
style.configure("TButton", foreground="black", background="black", font=("Helvetica", 14))
style.map("TButton", background=[("active", "#8791d5")])

# إعداد الحقول النصية والأزرار
ttk.Label(root, text="... النص المشفر ", font=("Courier New", 18,"bold"), background="#b8b0d2", foreground="black").grid(row=0, column=0, sticky="n", padx=40, pady=30)
#انشاء مربع النص الاول
text1 = tk.Text(root, height=3, width=10, bg="#ECF0F1", font=("Helvetica", 12), wrap="word", bd=4, relief="sunken", highlightbackground="#7851a9", highlightthickness=3)
text1.grid(row=0, column=0, padx=40, sticky="nsew",pady=70)


ttk.Label(root, text="... ادخل النص ", font=("Courier New", 18,"bold"), background="#b8b0d2", foreground="black").grid(row=0, column=2, sticky="n", padx=50, pady=30)
# إنشاء مربع النص الثاني
text2 = tk.Text(root,width=20, height=5, bg="#ECF0F1", font=("Helvetica", 12), wrap="word", bd=4, relief="sunken", highlightbackground="#7851a9", highlightthickness=3)
text2.grid(row=0, column=2, padx=40, sticky="nsew",pady=70)


# ضبط وزن الأعمدة والصفوف في إطار المربعات النصية
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(2, weight=1)
root.grid_rowconfigure(0, weight=1)

# ضبط وزن الأعمدة في نافذة الرئيسية لضمان توسيع الإطار
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)

# ضبط وزن الأعمدة والصفوف في إطار المربعات النصية
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(2, weight=1)
root.grid_rowconfigure(0, weight=1)

# توسيط إدخال كلمة المرور في النافذة
ttk.Label(root, text=": ادخل كلمة المرور ", font=24, background="#b8b0d2", foreground="black").grid(row=1, column=0, columnspan=3, sticky="n", padx=5, pady=50)
password_input = ttk.Entry(root, show='*', width=29, font=("Helvetica", 12))
password_input.grid(row=1, column=0, columnspan=3, sticky="n", padx=1, pady=90)

# تحميل أيقونات العين
eye_open_image = ImageTk.PhotoImage(Image.open("visible.png").resize((30, 30)))  # أيقونة العين المفتوحة
eye_closed_image = ImageTk.PhotoImage(Image.open("eye.png").resize((30, 30)))  # أيقونة العين المغلقة

# زر التبديل بين إظهار وإخفاء كلمة المرور
password_visible = False  # الحالة الأولية لإخفاء كلمة المرور
toggle_button = tk.Button(root, image=eye_closed_image, relief="flat", width=25, height=25 , command=toggle_password_visibility)
toggle_button.grid(row=1, column=2, sticky="wn", padx=40, pady=85)



# الأزرار للتشفير وفك التشفير
encrypt_button = tk.Button(root, text="التشفير", relief="raised", width="10", background="#7851a9" , command=encrypt_message)
encrypt_button.grid(row=1, column=2, sticky="n", padx=5, pady=10)

decrypt_button = tk.Button(root, text="فك التشفير",  relief="raised", width="10", background="#7851a9" , command=decrypt_message)
decrypt_button.grid(row=1, column=0, sticky="n", padx=5, pady=10)

# زر نسخ النص المشفر
copy_button = tk.Button(root, width=7,text="نسخ", relief="raised" ,command=copy_encrypted_message)
copy_button.grid(row=0, column=0, sticky="sw", padx=50, pady=10)


root.mainloop()
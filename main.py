import tkinter as tk
import base64

def encode(key, clear):
    try:
        if not key or not clear:
            raise ValueError("Both key and clear must not be empty")
        
        enc = []
        for i in range(len(clear)):
            key_c = key[i % len(key)]
            enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
            enc.append(enc_c)

        encoded_data = "".join(enc).encode()
        base64_encoded = base64.urlsafe_b64encode(encoded_data).decode()
        
        return base64_encoded
    except ValueError as ve:
        return str(ve)
    except Exception as e:
        return "An error occurred: " + str(e)

def decode(key, enc):
    try:
        if not key or not enc:
            raise ValueError("Both key and enc must not be empty")

        decoded_data = base64.urlsafe_b64decode(enc).decode()
        
        dec = []
        for i in range(len(decoded_data)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(decoded_data[i]) - ord(key_c)) % 256)
            dec.append(dec_c)

        return "".join(dec)
    except ValueError as ve:
        return str(ve)
    except Exception as e:
        return "An error occurred: " + str(e)

def show_result():
    try:
        clear = msg.get()
        k = key.get()
        m = mode.get()
        if not clear or not k:
            result.set("Both message and key must not be empty")
        elif m == 'e':
            result.set(encode(k, clear))
        elif m == 'd':
            result.set(decode(k, clear))
        else:
            result.set("Invalid mode. Use 'e' for encoding or 'd' for decoding.")
    except ValueError as ve:
        result.set(str(ve))
    except Exception as e:
        result.set("An error occurred: " + str(e))

def reset():
    try:
        rand.set("")
        msg.set("")
        key.set("")
        mode.set("")
        result.set("")
    except Exception as e:
        result.set(str(e))

def exit_app():
    try:
        root.destroy()
    except Exception as e:
        result.set(str(e)

root = tk.Tk()
root.geometry("1200x600")
root.title("Message Encryption and Decryption")

tops = tk.Frame(root, width=1600, relief=tk.SUNKEN)
tops.pack(side=tk.TOP)

dark_mode_button = tk.Button(tops, text="Toggle Dark Mode", command=toggle_dark_mode)
dark_mode_button.grid(row=0, column=1)

f1 = tk.Frame(root, width=800, height=700, relief=tk.SUNKEN)
f1.pack(side=tk.LEFT)

local_time = tk.asctime(tk.localtime(tk.time()))

label_info = tk.Label(tops, font=('helvetica', 50, 'bold'),
                      text="SECRET MESSAGING\n!!!For School Project Only!!!",
                      fg="Black", bd=10, anchor='w')
label_info.grid(row=1, column=0)

label_info = tk.Label(tops, font=('arial', 20, 'bold'),
                      text=local_time, fg="Steel Blue",
                      bd=10, anchor='w')
label_info.grid(row=2, column=0)

rand = tk.StringVar()
msg = tk.StringVar()
key = tk.StringVar()
mode = tk.StringVar()
result = tk.StringVar()

label_reference = tk.Label(f1, font=('arial', 16, 'bold'),
                           text="Name:", bd=16, anchor="w")
label_reference.grid(row=0, column=0)

entry_reference = tk.Entry(f1, font=('arial', 16, 'bold'),
                          textvariable=rand, bd=10, insertwidth=4,
                          bg="powder blue", justify='right')
entry_reference.grid(row=0, column=1)

label_msg = tk.Label(f1, font=('arial', 16, 'bold'),
                     text="MESSAGE", bd=16, anchor="w")
label_msg.grid(row=1, column=0)

entry_msg = tk.Entry(f1, font=('arial', 16, 'bold'),
                     textvariable=msg, bd=10, insertwidth=4,
                     bg="powder blue", justify='right')
entry_msg.grid(row=1, column=1)

label_key = tk.Label(f1, font=('arial', 16, 'bold'),
                     text="KEY", bd=16, anchor="w")
label_key.grid(row=2, column=0)

entry_key = tk.Entry(f1, font=('arial', 16, 'bold'),
                     textvariable=key, bd=10, insertwidth=4,
                     bg="powder blue", justify='right')
entry_key.grid(row=2, column=1)

label_mode = tk.Label(f1, font=('arial', 16, 'bold'),
                      text="MODE(e for encrypt, d for decrypt)",
                      bd=16, anchor="w")
label_mode.grid(row=3, column=0)

entry_mode = tk.Entry(f1, font=('arial', 16, 'bold'),
                      textvariable=mode, bd=10, insertwidth=4,
                      bg="powder blue", justify='right')
entry_mode.grid(row=3, column=1)

label_service = tk.Label(f1, font=('arial', 16, 'bold'),
                         text="The Result-", bd=16, anchor="w")
label_service.grid(row=2, column=2)

entry_service = tk.Entry(f1, font=('arial', 16, 'bold'),
                         textvariable=result, bd=10, insertwidth=4,
                         bg="powder blue", justify='right')
entry_service.grid(row=2, column=3)

button_show_message = tk.Button(f1, padx=16, pady=8, bd=16, fg="black",
                                font=('arial', 16, 'bold'), width=10,
                                text="Show Message", bg="powder blue",
                                command=show_result)
button_show_message.grid(row=7, column=1)

button_reset = tk.Button(f1, padx=16, pady=8, bd=16,
                         fg="black", font=('arial', 16, 'bold'),
                         width=10, text="Reset", bg="green",
                         command=reset)
button_reset.grid(row=7, column=2)

button_exit = tk.Button(f1, padx=16, pady=8, bd=16,
                        fg="black", font=('arial', 16, 'bold'),
                        width=10, text="Exit", bg="red",
                        command=exit_app)
button_exit.grid(row=7, column=3)

root.mainloop()

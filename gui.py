# gui.py
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import app

def on_browse():
    p = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, p)

def on_wipe():
    path = entry.get().strip()
    if not path:
        messagebox.showerror("Error", "Select a file")
        return
    def job():
        btn_wipe.config(state="disabled")
        try:
            j,pdf,s = app.run_wipe_and_issue(path, privkey="keys/priv.pem", passes=1)
            messagebox.showinfo("Done", f"JSON: {j}\nPDF: {pdf}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            btn_wipe.config(state="normal")
    threading.Thread(target=job, daemon=True).start()

root = tk.Tk()
root.title("Secure Wipe MVP")
root.geometry("520x150")
tk.Label(root, text="File to wipe (use testfile.bin):").pack(anchor="w", padx=10, pady=(8,0))
entry = tk.Entry(root, width=70)
entry.pack(padx=10)
frm = tk.Frame(root)
frm.pack(padx=10, pady=8)
tk.Button(frm, text="Browse", command=on_browse).pack(side="left")
btn_wipe = tk.Button(frm, text="Secure Wipe & Issue Cert", command=on_wipe, bg="red", fg="white")
btn_wipe.pack(side="left", padx=6)
root.mainloop()

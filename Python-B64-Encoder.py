# This program enables b64 encoding files to paste into other scripts or developments (Such as Sysmon-OneClick https://github.com/ACEThreat/SysmonONECLICK)
# Copyright 2024 ACEThreat
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# Created by Git: @ACEThreat
# LinkedIn: @snsl 
####################################################################################################################
import tkinter as tk
from tkinter import filedialog, messagebox
import base64
import pyperclip
import logging

# Set up logging to capture errors
logging.basicConfig(filename='error.log', level=logging.ERROR)

def encode_file_to_base64():
    # Open file dialog to select a file
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    try:
        # Read the file in binary mode
        with open(file_path, 'rb') as file:
            file_content = file.read()

        # Encode the file content to base64
        encoded_content = base64.b64encode(file_content)

        # Copy the encoded content to the clipboard
        pyperclip.copy(encoded_content.decode('ascii'))

        # Show a message box to confirm completion
        messagebox.showinfo("Success", "The file has been encoded and copied to the clipboard.")
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found.")
    except PermissionError:
        messagebox.showerror("Error", "Permission denied.")
    except Exception as e:
        logging.error("An unexpected error occurred", exc_info=True)
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    try:
        # Create the main application window
        root = tk.Tk()
        root.title("Base64 Encoder")
        root.geometry("300x150")

        # Create a button to trigger the encoding process
        encode_button = tk.Button(root, text="Encode File to Base64", command=encode_file_to_base64)
        encode_button.pack(pady=20)

        # Run the application
        root.mainloop()
    except Exception as e:
        logging.error("An unexpected error occurred during initialization", exc_info=True)
        print(f"An unexpected error occurred: {e}")
        input("Press Enter to exit...")  # Pause to view the error

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

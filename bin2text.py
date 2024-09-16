import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess

# Dictionnaire des opcodes 6502 avec leurs mnémoniques et modes d'adressage
opcodes = {
    0x00: ("BRK", "impl", 1), 0x01: ("ORA", "indx", 2), 0x05: ("ORA", "zp", 2), 0x06: ("ASL", "zp", 2),
    0x08: ("PHP", "impl", 1), 0x09: ("ORA", "imm", 2), 0x0A: ("ASL", "acc", 1), 0x0D: ("ORA", "abs", 3),
    0x0E: ("ASL", "abs", 3), 0x10: ("BPL", "rel", 2), 0x11: ("ORA", "indy", 2), 0x15: ("ORA", "zpx", 2),
    0x16: ("ASL", "zpx", 2), 0x18: ("CLC", "impl", 1), 0x19: ("ORA", "absy", 3), 0x1D: ("ORA", "absx", 3),
    0x1E: ("ASL", "absx", 3), 0x20: ("JSR", "abs", 3), 0x21: ("AND", "indx", 2), 0x24: ("BIT", "zp", 2),
    0x25: ("AND", "zp", 2), 0x26: ("ROL", "zp", 2), 0x28: ("PLP", "impl", 1), 0x29: ("AND", "imm", 2),
    0x2A: ("ROL", "acc", 1), 0x2C: ("BIT", "abs", 3), 0x2D: ("AND", "abs", 3), 0x2E: ("ROL", "abs", 3),
    0x30: ("BMI", "rel", 2), 0x31: ("AND", "indy", 2), 0x35: ("AND", "zpx", 2), 0x36: ("ROL", "zpx", 2),
    0x38: ("SEC", "impl", 1), 0x39: ("AND", "absy", 3), 0x3D: ("AND", "absx", 3), 0x3E: ("ROL", "absx", 3),
    0x40: ("RTI", "impl", 1), 0x41: ("EOR", "indx", 2), 0x45: ("EOR", "zp", 2), 0x46: ("LSR", "zp", 2),
    0x48: ("PHA", "impl", 1), 0x49: ("EOR", "imm", 2), 0x4A: ("LSR", "acc", 1), 0x4C: ("JMP", "abs", 3),
    0x4D: ("EOR", "abs", 3), 0x4E: ("LSR", "abs", 3), 0x50: ("BVC", "rel", 2), 0x51: ("EOR", "indy", 2),
    0x55: ("EOR", "zpx", 2), 0x56: ("LSR", "zpx", 2), 0x58: ("CLI", "impl", 1), 0x59: ("EOR", "absy", 3),
    0x5D: ("EOR", "absx", 3), 0x5E: ("LSR", "absx", 3), 0x60: ("RTS", "impl", 1), 0x61: ("ADC", "indx", 2),
    0x65: ("ADC", "zp", 2), 0x66: ("ROR", "zp", 2), 0x68: ("PLA", "impl", 1), 0x69: ("ADC", "imm", 2),
    0x6A: ("ROR", "acc", 1), 0x6C: ("JMP", "ind", 3), 0x6D: ("ADC", "abs", 3), 0x6E: ("ROR", "abs", 3),
    0x70: ("BVS", "rel", 2), 0x71: ("ADC", "indy", 2), 0x75: ("ADC", "zpx", 2), 0x76: ("ROR", "zpx", 2),
    0x78: ("SEI", "impl", 1), 0x79: ("ADC", "absy", 3), 0x7D: ("ADC", "absx", 3), 0x7E: ("ROR", "absx", 3),
    0x81: ("STA", "indx", 2), 0x84: ("STY", "zp", 2), 0x85: ("STA", "zp", 2), 0x86: ("STX", "zp", 2),
    0x88: ("DEY", "impl", 1), 0x8A: ("TXA", "impl", 1), 0x8C: ("STY", "abs", 3), 0x8D: ("STA", "abs", 3),
    0x8E: ("STX", "abs", 3), 0x90: ("BCC", "rel", 2), 0x91: ("STA", "indy", 2), 0x94: ("STY", "zpx", 2),
    0x95: ("STA", "zpx", 2), 0x96: ("STX", "zpy", 2), 0x98: ("TYA", "impl", 1), 0x99: ("STA", "absy", 3),
    0x9A: ("TXS", "impl", 1), 0x9D: ("STA", "absx", 3), 0xA0: ("LDY", "imm", 2), 0xA1: ("LDA", "indx", 2),
    0xA2: ("LDX", "imm", 2), 0xA4: ("LDY", "zp", 2), 0xA5: ("LDA", "zp", 2), 0xA6: ("LDX", "zp", 2),
    0xA8: ("TAY", "impl", 1), 0xA9: ("LDA", "imm", 2), 0xAA: ("TAX", "impl", 1), 0xAC: ("LDY", "abs", 3),
    0xAD: ("LDA", "abs", 3), 0xAE: ("LDX", "abs", 3), 0xB0: ("BCS", "rel", 2), 0xB1: ("LDA", "indy", 2),
    0xB4: ("LDY", "zpx", 2), 0xB5: ("LDA", "zpx", 2), 0xB6: ("LDX", "zpy", 2), 0xB8: ("CLV", "impl", 1),
    0xB9: ("LDA", "absy", 3), 0xBA: ("TSX", "impl", 1), 0xBC: ("LDY", "absx", 3), 0xBD: ("LDA", "absx", 3),
    0xBE: ("LDX", "absy", 3), 0xC0: ("CPY", "imm", 2), 0xC1: ("CMP", "indx", 2), 0xC4: ("CPY", "zp", 2),
    0xC5: ("CMP", "zp", 2), 0xC6: ("DEC", "zp", 2), 0xC8: ("INY", "impl", 1), 0xC9: ("CMP", "imm", 2),
    0xCA: ("DEX", "impl", 1), 0xCC: ("CPY", "abs", 3), 0xCD: ("CMP", "abs", 3), 0xCE: ("DEC", "abs", 3),
    0xD0: ("BNE", "rel", 2), 0xD1: ("CMP", "indy", 2), 0xD5: ("CMP", "zpx", 2), 0xD6: ("DEC", "zpx", 2),
    0xD8: ("CLD", "impl", 1), 0xD9: ("CMP", "absy", 3), 0xDD: ("CMP", "absx", 3), 0xDE: ("DEC", "absx", 3),
    0xE0: ("CPX", "imm", 2), 0xE1: ("SBC", "indx", 2), 0xE4: ("CPX", "zp", 2), 0xE5: ("SBC", "zp", 2),
    0xE6: ("INC", "zp", 2), 0xE8: ("INX", "impl", 1), 0xE9: ("SBC", "imm", 2), 0xEA: ("NOP", "impl", 1),
    0xEC: ("CPX", "abs", 3), 0xED: ("SBC", "abs", 3), 0xEE: ("INC", "abs", 3), 0xF0: ("BEQ", "rel", 2),
    0xF1: ("SBC", "indy", 2), 0xF5: ("SBC", "zpx", 2), 0xF6: ("INC", "zpx", 2), 0xF8: ("SED", "impl", 1),
    0xF9: ("SBC", "absy", 3), 0xFD: ("SBC", "absx", 3), 0xFE: ("INC", "absx", 3)
}

def bin2txt(binary_file, start_address, output_file):
    with open(binary_file, 'rb') as f:
        binary_data = f.read()

    with open(output_file, 'w') as out:
        address = start_address
        i = 0
        while i < len(binary_data):
            opcode = binary_data[i]
            if opcode in opcodes:
                mnemonic, addr_mode, length = opcodes[opcode]
                hex_bytes = ' '.join([f'{b:02X}' for b in binary_data[i:i+length]])
                hex_bytes = hex_bytes.ljust(12)

                operand = None
                if length > 1:
                    if length == 2:
                        operand = binary_data[i+1]
                    elif length == 3:
                        operand = binary_data[i+1] + (binary_data[i+2] << 8)

                instruction = format_instruction(mnemonic, addr_mode, operand, address, binary_data, i, start_address)
                out.write(f'{address:04X}:{hex_bytes}{instruction}\n')

                i += length
                address += length
            else:
                out.write(f'{address:04X}:{binary_data[i]:02X}                   ???\n')
                i += 1
                address += 1

def format_instruction(mnemonic, addr_mode, operand, address, binary_data, index, start_address):
    if addr_mode == "impl" or addr_mode == "acc":
        return mnemonic
    elif addr_mode == "imm":
        return f"{mnemonic} #${operand:02X}"
    elif addr_mode == "zp":
        return f"{mnemonic} ${operand:02X}"
    elif addr_mode == "zpx":
        return f"{mnemonic} ${operand:02X},X"
    elif addr_mode == "zpy":
        return f"{mnemonic} ${operand:02X},Y"
    elif addr_mode == "indx":
        return f"{mnemonic} (${operand:02X},X)"
    elif addr_mode == "indy":
        return f"{mnemonic} (${operand:02X}),Y"
    elif addr_mode == "abs":
        return f"{mnemonic} ${operand:04X}"
    elif addr_mode == "absx":
        return f"{mnemonic} ${operand:04X},X"
    elif addr_mode == "absy":
        return f"{mnemonic} ${operand:04X},Y"
    elif addr_mode == "ind":
        if operand >= start_address and operand<len(binary_data): # attention de ne pas aller chercher des adresses en dehors du tableau binaire chargé
            indirect_address = binary_data[operand-start_address] + (binary_data[operand -start_address + 1] << 8)
            return f"{mnemonic} (${operand:04X})=>${indirect_address:04X}"
        return f"{mnemonic} (${operand:04X})"
    elif addr_mode == "rel":
        target = address + 2 + (operand if operand < 128 else operand - 256)
        return f"{mnemonic} ${target:04X}"
    else:
        return f"{mnemonic} ${operand:04X}"

class DisassemblerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Désassembleur 6502")
        master.geometry("600x300")

        self.binary_file_path = tk.StringVar()
        self.text_file_path = tk.StringVar()
        self.start_address = tk.StringVar()

        # Frame pour la sélection du fichier binaire
        binary_frame = tk.LabelFrame(master, text="Fichier binaire", padx=5, pady=5)
        binary_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(binary_frame, text="Fichier:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        tk.Entry(binary_frame, textvariable=self.binary_file_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(binary_frame, text="Parcourir", command=self.browse_binary_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(binary_frame, text="Adresse de début (hex):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        tk.Entry(binary_frame, textvariable=self.start_address, width=10).grid(row=1, column=1, sticky="w", padx=5, pady=5)

        tk.Button(binary_frame, text="Désassembler", command=self.disassemble).grid(row=1, column=2, pady=10)

        # Frame pour la sélection du fichier texte
        text_frame = tk.LabelFrame(master, text="Fichier texte", padx=5, pady=5)
        text_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(text_frame, text="Fichier:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        tk.Entry(text_frame, textvariable=self.text_file_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(text_frame, text="Parcourir", command=self.browse_text_file).grid(row=0, column=2, padx=5, pady=5)

        # Bouton pour générer le HTML
        self.generate_html_button = tk.Button(master, text="Générer HTML", command=self.generate_html_output, state=tk.DISABLED)
        self.generate_html_button.pack(pady=10)

        # Bouton pour ouvrir l'explorateur
        tk.Button(master, text="Ouvrir l'Explorateur", command=self.open_explorer).pack(pady=10)

        # Surveiller les changements dans le chemin du fichier texte
        self.text_file_path.trace_add("write", self.check_text_file)

    def browse_binary_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin")])
        self.binary_file_path.set(filename)

    def browse_text_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.text_file_path.set(filename)

    def check_text_file(self, *args):
        if self.text_file_path.get():
            self.generate_html_button.config(state=tk.NORMAL)
        else:
            self.generate_html_button.config(state=tk.DISABLED)

    def open_explorer(self):
        if self.binary_file_path.get():
            folder_path = os.path.dirname(self.binary_file_path.get())
        elif self.text_file_path.get():
            folder_path = os.path.dirname(self.text_file_path.get())
        else:
            folder_path = os.path.expanduser("~")
        
        try:
            if sys.platform == "win32":
                os.startfile(folder_path)
            elif sys.platform == "darwin":  # macOS
                subprocess.call(["open", folder_path])
            else:  # linux variants
                subprocess.call(["xdg-open", folder_path])
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'ouvrir l'explorateur : {str(e)}")

    def generate_html_output(self):
        txt_file = self.text_file_path.get()
        if not txt_file:
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier texte.")
            return

        html_file = os.path.splitext(txt_file)[0] + ".html"

        try:
            self.generate_html(txt_file, html_file)
            messagebox.showinfo("Succès", f"Fichier HTML généré : {html_file}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur est survenue lors de la génération du fichier HTML : {str(e)}")

    def disassemble(self):
        input_file = self.binary_file_path.get()
        if not input_file:
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier binaire.")
            return

        try:
            start_address = int(self.start_address.get(), 16)
        except ValueError:
            messagebox.showerror("Erreur", "Adresse de début invalide. Utilisez un format hexadécimal valide.")
            return

        output_file = os.path.splitext(input_file)[0] + ".txt"

        try:
            bin2txt(input_file, start_address, output_file)
            messagebox.showinfo("Succès", f"Désassemblage terminé. Résultat écrit dans {output_file}")
            self.text_file_path.set(output_file)  # Mettre à jour le chemin du fichier texte
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur est survenue lors du désassemblage : {str(e)}")
    def generate_html(self, txt_file, html_file):
        with open(txt_file, 'r') as f:
            lines = f.readlines()

        # Create a dictionary to store instruction addresses
        address_dict = {}
        for line in lines:
            parts = line.split(':')
            if len(parts) >= 2:
                address = parts[0].strip()
                address_dict[address] = True

        with open(html_file, 'w') as f:
            f.write('''
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Désassemblage 6502</title>
        <style>
            body { font-family: monospace; line-height: 1.5; }
            a { color: #0066cc; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .comment { color: #008000; }
        </style>
    </head>
    <body>
    <pre>
    ''')

            for line in lines:
                parts = line.split(';', 1)
                instruction_part = parts[0]
                comment_part = parts[1] if len(parts) > 1 else ''

                address_parts = instruction_part.split(':')
                if len(address_parts) >= 2:
                    address = address_parts[0].strip()
                    instruction = ':'.join(address_parts[1:]).strip()

                    # Add an identifier for each line
                    f.write(f'<span id="{address}">{address}: ')

                    # Check if the instruction is JMP, JSR, a branch, or an indirect instruction
                    if any(instr in instruction for instr in ['JMP', 'JSR', 'BNE', 'BEQ', 'BMI', 'BPL', 'BVC', 'BVS', 'BCC', 'BCS']):
                        # Extract the target address
                        if '(' in instruction and ')' in instruction:  # Indirect addressing
                            target_address = instruction.split('(')[1].split(')')[0].strip('$')
                            if '=>' in instruction:  # If the indirect address is resolved
                                resolved_address = instruction.split('=>')[1].strip().split()[0]
                                if resolved_address in address_dict:
                                    f.write(f'{instruction.split("(")[0]}(<a href="#{target_address}">${target_address}</a>)=>')
                                    f.write(f'<a href="#{resolved_address}">${resolved_address}</a>')
                                else:
                                    f.write(instruction)
                            else:
                                f.write(f'{instruction.split("(")[0]}(<a href="#{target_address}">${target_address}</a>)')
                        else:  # Direct addressing
                            target_address = instruction.split('$')[-1].split()[0]
                            if target_address in address_dict:
                                f.write(f'{instruction.split("$")[0]}<a href="#{target_address}">${target_address}</a>')
                            else:
                                f.write(instruction)
                    else:
                        f.write(instruction)

                    f.write('</span>')

                    # Add the comment if it exists
                    if comment_part:
                        f.write(f'<span class="comment">\t; {comment_part.strip()}</span>')

                    f.write('\n')
                else:
                    f.write(f'<span class="comment">{line}</span>')

            f.write('''
    </pre>
    </body>
    </html>
    ''')


if __name__ == "__main__":
    root = tk.Tk()
    gui = DisassemblerGUI(root)
    root.mainloop()
# Project Python ICN
# Modified 28/04/2019
# Subject : Tool de binanalysis
# By nasm and anubilis


import tkinter as tk
import tkinter.messagebox as msg
from tkinter import filedialog
import platform
import pefile
import peutils


class Root(tk.Tk):
    # L'Utilisateur Ferme la Fenetre Section
    def sections_del(self):
        self.deiconify()
        self.section.withdraw()

    # L'Utilisateur Ferme la Fenetre Imports
    def imports_del(self):
        self.deiconify()
        self.imports.withdraw()

    # L'Utilisateur Ferme la Fenetre image Dos Header
    def img_dos_header_del(self):
        self.deiconify()
        self.img_dos_header.withdraw()

    # L'Utilisateur Presse le Bouton pour voir les Sections
    def sections_show(self):
        self.withdraw()
        self.section.deiconify()

    # L'Utilisateur Presse le Bouton pour voir les Imports
    def imports_show(self):
        self.withdraw()
        self.imports.deiconify()

    # L'Utilisateur Presse le Bouton pour voir les Images Dos Header
    def img_dos_header_show(self):
        self.withdraw()
        self.img_dos_header.deiconify()

    # Positionnement pour l'Utilisateur Windows 
    def lancement_windows(self):
        self.lb_file.place(x=10, y=8)
        self.bt_file_explorer.place(x=750, y=10)
        self.e_file.place(x=70, y=13)
        self.e_file.config(width=74)

        self.lb_entrypoint.place(x=20, y=75)
        self.e_entrypoint.place(x=175, y=80)

        self.lb_imagebase.place(x=20, y=130)
        self.e_imagebase.place(x= 175, y=135)

        self.lb_nb_sections.place(x=20, y=185)
        self.e_nb_sections.place(x=220, y=190)

        self.e_packer.pack(side='bottom', pady=20)

        self.lb_section_info.place(x=400, y=75)
        self.e_section_info.place(x=600, y=80)
        self.bt_watch_sections.place(x=730, y=75)

        self.lb_imports_info.place(x=400, y=130)
        self.e_imports_info.place(x=600, y=135)
        self.bt_watch_imports.place(x=730, y=130)

        self.lb_img_dos_header_info.place(x=400, y=185)
        self.e_img_dos_header_info.place(x=600, y=190)
        self.bt_watch_img_dos_header.place(x=730, y=185)

        self.txt_sections.pack(side='top')
        self.txt_imports.pack(side='top')
        self.txt_img_dos_header.pack(side='top')

    # Positionnement pour l'Utilisateur Linux
    def lancement_linux(self):
        self.lb_file.place(x=10, y=8)
        self.bt_file_explorer.place(x=750, y=8)
        self.e_file.place(x=70, y=10)
        self.e_file.config(width=60)

        self.lb_entrypoint.place(x=20, y=75)
        self.e_entrypoint.place(x=185, y=75)

        self.lb_imagebase.place(x=20, y=130)
        self.e_imagebase.place(x= 185, y=130)

        self.lb_nb_sections.place(x=20, y=185)
        self.e_nb_sections.place(x=240, y=185)

        self.e_packer.pack(side='bottom', pady=20)

        self.lb_section_info.place(x=410, y=75)
        self.e_section_info.place(x=620, y=80)
        self.bt_watch_sections.place(x=750, y=75)

        self.lb_imports_info.place(x=410, y=130)
        self.e_imports_info.place(x=620, y=135)
        self.bt_watch_imports.place(x=750, y=130)

        self.lb_img_dos_header_info.place(x=410, y=185)
        self.e_img_dos_header_info.place(x=620, y=185)
        self.bt_watch_img_dos_header.place(x=750, y=185)

        self.txt_sections.pack(side='top')
        self.txt_imports.pack(side='top')
        self.txt_img_dos_header.pack(side='top')

    # L'Utilisateur appuie sur la croix rouge pour quitter
    def off(self):
        question = msg.askquestion("Wait...", "Do you want leave?")
        if question == "yes":
            self.destroy()
            self.section.destroy()
            self.imports.destroy()
            self.img_dos_header.destroy()
        else:
            pass

    # L'Utilisateur Presse le Bouton Explorateur de Fichier
    def file_explorer(self):
        global source
        source = filedialog.askopenfilename(title="Explorateur de Fichiers", initialdir="C://", filetypes=[("Application", "*.exe")])
        if len(source) > 0:
            self.e_file.config(state='normal')
            self.e_file.delete(0, 'end')
            self.e_file.insert(0, source)
            self.e_file.config(state='disabled')
            self.analyse()
        else:
            pass

    # L'Ananlyse Commence
    def analyse(self):
        global source, len_all_sections
        len_all_sections = 0
        pe = pefile.PE(str(source))
        # Valeur EntryPoint ( Hexa )
        self.e_entrypoint.config(state='normal')
        self.e_entrypoint.delete(0, 'end')
        self.e_entrypoint.insert(0, hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        self.e_entrypoint.config(state='disabled')

        # Valeur ImageBase ( Hexa )
        self.e_imagebase.config(state='normal')
        self.e_imagebase.delete(0, 'end')
        self.e_imagebase.insert(0, hex(pe.OPTIONAL_HEADER.ImageBase))
        self.e_imagebase.config(state='disabled')

        # Nombre de Sections
        self.e_nb_sections.config(state='normal')
        self.e_nb_sections.delete(0, 'end')
        self.e_nb_sections.insert(0, "{}".format(pe.FILE_HEADER.NumberOfSections))
        self.e_nb_sections.config(state='disabled')

        # Packer
        signatures = peutils.SignatureDatabase('Data/userdb.txt')
        matches = signatures.match(pe, ep_only = True)
        if matches == None:
            self.e_packer.config(state='normal')
            self.e_packer.delete(0, 'end')
            self.e_packer.insert(10, "  [-] Packer not found")
            self.e_packer.config(state='disabled')
        else:
            self.e_packer.config(state='normal')
            self.e_packer.delete(0, 'end')
            self.e_packer.insert(0, matches)
            self.e_packer.config(state='disabled')
        
        # Len All Sections ( Hexa )
        for sec in pe.sections:
            len_all_sections += sec.SizeOfRawData
        self.e_section_info.config(state='normal')
        self.e_section_info.delete(0, 'end')
        self.e_section_info.insert(0, hex(len_all_sections))
        self.e_section_info.config(state='disabled')

        # Sections Description
        self.bt_watch_sections.config(state='normal')
        self.txt_sections.config(state='normal')
        self.txt_sections.delete(0.0, 'end')
        for sec in pe.sections:
            sec.Name = str(sec.Name)
            sec.Name = sec.Name.replace("b'", "")
            sec.Name = sec.Name.replace("\\x00\\x00\\x00'", "")

            if sec.Name == ".reloc\\x00\\x00'":
                sec.Name = sec.Name.replace("\\x00\\x00'", "")

            sec.Name = sec.Name.replace("\\x00", "")
            self.txt_sections.insert('end', "{} at {} Size of raw_data (in {} section) : {}\n\n".format(str(sec.Name), 
                                                                                        hex(sec.VirtualAddress), 
                                                                                        str(sec.Name), hex(sec.SizeOfRawData)))
        self.txt_sections.config(state='disabled')

        # Imports Description and Number
        self.bt_watch_imports.config(state='normal')
        compteur = 0
        self.txt_imports.config(state='normal')
        self.txt_imports.delete(0.0, 'end')
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            compteur += 1
            self.txt_imports.insert('end', "{}\n".format(entry.dll.decode('utf-8')))
            for imp in entry.imports:
                self.txt_imports.insert('end', ('\t{} \t{}\n'.format(hex(imp.address), imp.name.decode('utf-8'))))
            self.txt_imports.insert('end', '\n')
        self.txt_imports.config(state='disabled')
        self.e_imports_info.config(state='normal')
        self.e_imports_info.delete(0, 'end')
        self.e_imports_info.insert(0, str(compteur))
        self.e_imports_info.config(state='disabled')

        # Image Dos Header Description and Number
        self.bt_watch_img_dos_header.config(state='normal')
        p = 0
        compteur = 0
        self.txt_img_dos_header.config(state='normal')
        self.txt_img_dos_header.delete(0.0, 'end')
        for field in pe.DOS_HEADER.dump():
            compteur += 1
            if p == 0:
                self.txt_img_dos_header.insert('end', "{}\n\n".format(field))
            else: 
                self.txt_img_dos_header.insert('end', "[*]        [-]\n")
                self.txt_img_dos_header.insert('end', "{}\n".format(field))
            p += 1
        self.txt_img_dos_header.config(state='disabled')
        self.e_img_dos_header_info.config(state='normal')
        self.e_img_dos_header_info.delete(0, 'end')
        self.e_img_dos_header_info.insert(0, str(compteur))
        self.e_img_dos_header_info.config(state='disabled')


    def __init__(self):
        # Init Tk()
        super().__init__()

        # Fenetre Principale
        self.geometry('800x320')
        self.config(bg='white')
        self.resizable(height=False, width=False)
        self.title('REsearch')
        self.protocol("WM_DELETE_WINDOW", self.off)
        if platform.system() == 'Windows':
        	self.iconbitmap("Data/ida.ico")
        elif platform.system() == "Linux":
        	pass

        # Creation Fenetre Section
        self.section = tk.Tk()
        self.section.geometry('800x500')
        self.section.config(bg='white')
        self.section.title('Sections Viewer')
        self.section.resizable(height=False, width=False)
        self.section.protocol("WM_DELETE_WINDOW", self.sections_del)
        self.section.withdraw()

        # Creation Fenetre Imports
        self.imports = tk.Tk()
        self.imports.geometry('800x500')
        self.imports.config(bg='white')
        self.imports.title('Imports Viewer')
        self.imports.resizable(height=False, width=False)
        self.imports.protocol("WM_DELETE_WINDOW", self.imports_del)
        self.imports.withdraw()

        # Creation Fenetre Image Dos Header
        self.img_dos_header = tk.Tk()
        self.img_dos_header.geometry('800x500')
        self.img_dos_header.config(bg='white')
        self.img_dos_header.title('Sections Viewer')
        self.img_dos_header.resizable(height=False, width=False)
        self.img_dos_header.protocol("WM_DELETE_WINDOW", self.img_dos_header_del)
        self.img_dos_header.withdraw()

        # Creation Label Informatif File
        self.lb_file = tk.Label(self, text='File  : ', bg='white', 
                                    fg='black', font=('verdata', 15))


        # Creation Bouton Explorateur de Fichier
        self.bt_file_explorer = tk.Button(self, command=self.file_explorer, text='...', 
                                                bg='white', fg='black', font=('verdata', 11))


        # Creation Entry Recevant l'Adresse du Fichier
        self.e_file = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
                                    state='disabled', disabledbackground='white', 
                                    disabledforeground='black')

        # Creation Label Informatif Adresse EntryPoint
        self.lb_entrypoint = tk.Label(self, text='EntryPoint  : ', bg='white', 
                                    fg='black', font=('verdata', 15))

        # Creation Entry Stockant l'Adresse de l'Entrypoint ( Hexa )
        self.e_entrypoint = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
                                    width=15, state='disabled', disabledbackground='white', 
                                    disabledforeground='black', justify='center')

        # Creation Label Informatif ImageBase
        self.lb_imagebase = tk.Label(self, text='ImageBase  : ', bg='white', 
                                    fg='black', font=('verdata', 15))

        # Creation Entry Stockant la Valeur ImageBase ( Hexa )
        self.e_imagebase = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
                                    width=15, state='disabled', disabledbackground='white', 
                                    disabledforeground='black', justify='center')

        # Creation Label Informatif Nombre de Sections
        self.lb_nb_sections = tk.Label(self, text='Number of Sections  : ', bg='white', 
                                    fg='black', font=('verdata', 15))

        # Creation Entry Stockant le Nombre de Sections
        self.e_nb_sections = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
                                    width=10, state='disabled', disabledbackground='white', 
                                    disabledforeground='black', justify='center')

        # Creation Entry Stockant Packer
        self.e_packer = tk.Entry(self, bg='white', fg='black', font=('verdata', 20), 
                                    width=30, state='disabled', disabledbackground='white', 
                                    disabledforeground='black', justify='center')

        # Creation Label Informatif Sections
        self.lb_section_info = tk.Label(self, text='Sections Info  : ', bg='white', 
                                    fg='black', font=('verdata', 15))
        
        # Creation Entry Stockant Toatal Sections ( Hexa )
        self.e_section_info = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
                                    width=10, state='disabled', disabledbackground='white', 
                                    disabledforeground='black', justify='center')
        
        # Creation Bouton Details Sections
        self.bt_watch_sections = tk.Button(self, command=self.sections_show, 
                                                text='[*]', bg='white', fg='black', 
                                                font=('verdata', 11), state='disabled')

        # Creation Zone de Text Fenetre Sections
        self.txt_sections = tk.Text(self.section, width=100, height=32, fg='green', background='black', 
                                                font=('verdata', 15), state='disabled')

         # Creation Label Informatif Imports
        self.lb_imports_info = tk.Label(self, text='Number of Imports : ', bg='white', 
                                    fg='black', font=('verdata', 15))

        # Creation Entry Stockant le Nombre de Imports
        self.e_imports_info = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
                                    width=10, state='disabled', disabledbackground='white', 
                                    disabledforeground='black', justify='center')

        # Creation Bouton Details Imports
        self.bt_watch_imports = tk.Button(self, command=self.imports_show, 
                                                text='[*]', bg='white', fg='black', 
                                                font=('verdata', 11), state='disabled')

        # Creation Zone de Text Fenetre Imports
        self.txt_imports = tk.Text(self.imports, width=100, height=32, fg='green', background='black', 
                                                font=('verdata', 15), state='disabled')

        # Creation Label Informatif Image Dos Header
        self.lb_img_dos_header_info = tk.Label(self, text='Image Dos Header : ', bg='white', 
                                    fg='black', font=('verdata', 15))

        # Creation Entry Stockant le Nombre de Image Dos Header
        self.e_img_dos_header_info = tk.Entry(self, bg='white', fg='black', font=('verdata', 13), 
                                    width=10, state='disabled', disabledbackground='white', 
                                    disabledforeground='black', justify='center')

        # Creation Bouton Details Image Dos Header
        self.bt_watch_img_dos_header = tk.Button(self, command=self.img_dos_header_show, 
                                                text='[*]', bg='white', fg='black', 
                                                font=('verdata', 11), state='disabled')

        # Creation Zone de Text Fenetre Image Dos Header
        self.txt_img_dos_header = tk.Text(self.img_dos_header, width=100, height=32, fg='green', background='black', 
                                                font=('verdata', 15), state='disabled')


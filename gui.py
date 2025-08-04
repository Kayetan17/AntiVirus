import os
import joblib
import customtkinter as ctk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox

from engine.scanner import scan_path, summarize
from engine.rule_manager import load_ruleset

purple = "#7850f1"
background = "#131313"
cardbackground = "#1E1E1E"
text = "#E3E3E3"

ctk.set_appearance_mode("dark")
ctk.set_widget_scaling(1.0)


class JackalGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.model = joblib.load("ml_model/static_model.joblib")
        self.yara_rules = load_ruleset("yara_rules/rules/")

        self.title("Jackal Antivirus")
        self.geometry("940x600")
        self.resizable(False, False)
        self.configure(fg_color=background)

        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.results_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True)

        self._build_main_screen()
        self._build_results_screen()

    def _build_main_screen(self):
        title_font = _try_font("LEMON MILK", 86)
        header_font = _try_font("LEMON MILK", 22)
        button_font = _try_font("LEMON MILK", 22)
        italic_font = _try_font("Inter", 20, italic=True)

        ctk.CTkLabel(self.main_frame, text="Jackal",
                     font=title_font, text_color=purple).place(relx=0.5, y=18, anchor="n")
        ctk.CTkLabel(self.main_frame,
                     text="Machine-learning and signature-based protection",
                     font=italic_font, text_color=text).place(relx=0.5, y=125, anchor="n")
        ctk.CTkFrame(self.main_frame, fg_color=purple, height=2).place(relx=0.16, rely=0.275, relwidth=0.68)

        opts = ctk.CTkFrame(self.main_frame, fg_color=cardbackground,
                            corner_radius=14, border_color="#2E2E2E", border_width=1)
        opts.place(relx=0.07, rely=0.33, relwidth=0.38, relheight=0.46)

        ctk.CTkLabel(opts, text="Scan Options",
                     font=header_font, text_color=purple).pack(pady=(18, 12))

        self.use_ml = ctk.BooleanVar(value=True)
        self.use_yara = ctk.BooleanVar(value=True)

        ml_row = ctk.CTkFrame(opts, fg_color="transparent")
        ml_row.pack(anchor="w", padx=28, pady=8)
        ctk.CTkSwitch(ml_row, text="Machine Learning Detection",
                      variable=self.use_ml, progress_color=purple,
                      fg_color="#555555", text_color=text).pack(side="left")

        info = ctk.CTkLabel(ml_row, text="ⓘ", text_color="#9A9A9A",
                            font=("Arial", 15, "bold"),
                            cursor="hand2", width=18)
        info.pack(side="left", padx=(6, 0))
        info.bind("<Button-1>", lambda _: messagebox.showinfo(
            "ML Scan", "Only scans PE files (.exe, .dll, .sys)."))

        ctk.CTkSwitch(opts, text="Signature Based Detection",
                      variable=self.use_yara, progress_color=purple,
                      fg_color="#555555", text_color=text).pack(anchor="w", padx=28, pady=8)

        path = ctk.CTkFrame(self.main_frame, fg_color=cardbackground,
                            corner_radius=14, border_color="#2E2E2E", border_width=1)
        path.place(relx=0.55, rely=0.33, relwidth=0.38, relheight=0.46)

        ctk.CTkLabel(path, text="Path Selection",
                     font=header_font, text_color=purple).pack(pady=(18, 12))

        self.path_choice = ctk.StringVar(value="file")
        row = ctk.CTkFrame(path, fg_color="transparent")
        row.pack(pady=6)
        ctk.CTkRadioButton(row, text="File", variable=self.path_choice,
                           value="file", fg_color=purple, hover_color=purple,
                           border_color=purple, text_color=text).pack(side="left", padx=10)
        ctk.CTkRadioButton(row, text="Folder", variable=self.path_choice,
                           value="folder", fg_color=purple, hover_color=purple,
                           border_color=purple, text_color=text).pack(side="left", padx=10)

        self.path_entry = ctk.CTkEntry(path, width=310,
                                       placeholder_text="Select a file or folder…")
        self.path_entry.pack(pady=10, padx=26)

        ctk.CTkButton(path, text="Browse", fg_color=purple, hover_color=purple,
                      width=120, command=self._browse).pack(pady=14)

        ctk.CTkButton(self.main_frame, text="Scan", fg_color=purple,
                      hover_color=purple, font=button_font,
                      width=180, height=46, corner_radius=12,
                      command=self._run_scan).place(relx=0.5, rely=0.9, anchor="center")

    def _build_results_screen(self):
        header_font = _try_font("LEMON MILK", 26)
        ctk.CTkLabel(self.results_frame, text="Scan Summary",
                     font=header_font, text_color=purple).pack(pady=(28, 10))

        self.summary_box = ctk.CTkTextbox(self.results_frame, width=880, height=350,
                                          fg_color=cardbackground, text_color=text,
                                          corner_radius=10, wrap="none")
        self.summary_box.pack(pady=10)
        self.summary_box.configure(state="disabled")

        ctk.CTkButton(self.results_frame, text="Return",
                      fg_color=purple, hover_color=purple,
                      font=_try_font("LEMON MILK", 20),
                      width=200, height=44, corner_radius=12,
                      command=self._return_home).pack(pady=20)

    def _browse(self):
        if self.path_choice.get() == "file":
            picker = filedialog.askopenfilename
        else:
            picker = filedialog.askdirectory
        p = picker()
        if p:
            self.path_entry.delete(0, ctk.END)
            self.path_entry.insert(0, p)

    def _run_scan(self):
        path = self.path_entry.get()
        if not path:
            messagebox.showwarning("No path selected", "Please choose a file or folder.")
            return
        res = scan_path(path, self.use_ml.get(), self.use_yara.get(),
                        model=self.model, yara_rules=self.yara_rules)
        self._populate_results(res)
        self._swap_to_results()

    def _populate_results(self, results):
        stats = summarize(results)
        threats = []
        for r in results:
            if r["ml_result"] == "malware":
                threats.append(r["file_path"])
            elif r["yara_result"].startswith("malware"):
                threats.append(r["file_path"])

        lines = [
            f"Files scanned : {stats['total']}",
            f"Threats found : {len(threats)}",
            f"ML malware    : {stats['ml_malware']}",
            f"YARA malware  : {stats['yara_malware']}",
            ""
        ]
        if threats:
            lines.extend(threats)
        else:
            lines.append("No threats detected.")

        self.summary_box.configure(state="normal")
        self.summary_box.delete("0.0", "end")
        self.summary_box.insert("end", "\n".join(lines))
        self.summary_box.configure(state="disabled")

    def _swap_to_results(self):
        self.main_frame.pack_forget()
        self.results_frame.pack(fill="both", expand=True)

    def _return_home(self):
        self.results_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)


def _try_font(family, size, weight="normal", italic=False):
    available = tkfont.families()
    if family in available:
        chosen = family
    else:
        chosen = "Helvetica"
    if italic:
        slant = "italic"
    else:
        slant = "roman"
    return (chosen, size, weight, slant)


if __name__ == "__main__":
    JackalGUI().mainloop()

import os
import re
import json
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import scrolledtext, ttk

import pandas as pd

# 若你已安裝 pyshark
try:
    import pyshark
except:
    pyshark = None



# 自動讀取 config.json 的 API Key（若存在）
def load_api_key():
    # 讀環境變數（最優先）
    key = os.environ.get("OPENAI_API_KEY")
    if key:
        return key

    # 再嘗試讀 config.json（如果用 PyInstaller，要配合 resource_path）
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                if "openai_api_key" in cfg:
                    return cfg["openai_api_key"]
        except:
            pass

    return None

class OMCIAnalyzerApp:



    def __init__(self, root):
        self.root = root
        self.root.title("PON OMCI Packets Analysis Tool v5.0")
        self.root.geometry("1200x900")

        self.current_pcap = None
        self.packets = []
        self.decoded_packets = []   # parsed results

        # ---- Status Bar ----
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                              anchor="w", relief="sunken")
        status_bar.pack(side="bottom", fill="x")

        # ---- Menu ----
        self.menu = tk.Menu(root)
        root.config(menu=self.menu)

        # File Menu
        file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open PCAP/PCAPNG", command=self.load_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)

        # OMCI Menu
        self.omci_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="OMCI", menu=self.omci_menu)
        self.omci_menu.add_command(label="Extract OMCI Packets", command=self.extract_omci_packets)
        self.omci_menu.add_command(label="Parse OMCI (Regex)", command=self.parse_extracted_omci)
        self.omci_menu.add_command(label="Export Excel", command=self.export_excel)

        # ---- AI Menu ----
        self.ai_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="AI 工具", menu=self.ai_menu)

        self.ai_menu.add_command(
            label="AI 解釋目前畫面的 OMCI 封包",
            command=self.ai_explain_current_omci
        )

        self.ai_menu.add_command(
            label="AI 總結整檔 OMCI (PCAP/PCAPNG)",
            command=self.ai_summary_pcap
        )

        self.ai_menu.add_command(
            label="AI 比對 Parser vs Wireshark（單一封包）",
            command=self.ai_compare_parser_vs_wireshark
        )

        self.ai_menu.add_command(
            label="AI 產生 Test Cases",
            command=self.ai_generate_testcases_for_current_omci
        )

        # ---- Main Frames ----
        self.build_main_frames()


    def build_main_frames(self):
        # Left = packet list
        left_frame = tk.Frame(self.root)
        left_frame.pack(side="left", fill="y")

        tk.Label(left_frame, text="Packet List").pack()
        self.packet_listbox = tk.Listbox(left_frame, width=40)
        self.packet_listbox.pack(fill="y", expand=False)
        self.packet_listbox.bind("<<ListboxSelect>>", self.on_packet_select)

        # Right = packet display
        right_frame = tk.Frame(self.root)
        right_frame.pack(side="right", fill="both", expand=True)

        tk.Label(right_frame, text="Packet Decode").pack()

        self.packet_display = scrolledtext.ScrolledText(
            right_frame, wrap="word", font=("Consolas", 11)
        )
        self.packet_display.pack(fill="both", expand=True)


    ############################################
    # PCAP Loading
    ############################################
    def load_pcap(self):
        if pyshark is None:
            messagebox.showerror("PyShark Missing", "未安裝 pyshark，請執行 pip install pyshark")
            return

        pcap = filedialog.askopenfilename(
            title="選擇 PCAP / PCAPNG",
            filetypes=[("PCAP/PCAPNG", "*.pcap *.pcapng"), ("All Files", "*.*")]
        )
        if not pcap:
            return

        self.status_var.set("Loading PCAP...")
        self.root.update_idletasks()

        try:
            cap = pyshark.FileCapture(pcap)
            self.packets = [pkt for pkt in cap]
            cap.close()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        self.current_pcap = pcap
        self.packet_listbox.delete(0, tk.END)
        for i, pkt in enumerate(self.packets):
            time = pkt.sniff_timestamp if hasattr(pkt, "sniff_timestamp") else "N/A"
            line = f"#{i+1}  [{time}] {pkt.highest_layer}"
            self.packet_listbox.insert(tk.END, line)

        self.status_var.set(f"Loaded {len(self.packets)} packets")


    ############################################
    # Extract OMCI Packets
    ############################################
    def extract_omci_packets(self):
        if pyshark is None:
            messagebox.showerror("PyShark Missing", "未安裝 pyshark")
            return

        if not self.current_pcap:
            messagebox.showwarning("Warning", "請先開啟 PCAP")
            return

        self.status_var.set("Extracting OMCI packets...")
        self.root.update_idletasks()

        cap = pyshark.FileCapture(self.current_pcap, display_filter="omci")
        omci_list = [pkt for pkt in cap]
        cap.close()

        self.packets = omci_list

        self.packet_listbox.delete(0, tk.END)
        for i, pkt in enumerate(omci_list):
            line = f"OMCI Packet {i+1} - HighestLayer={pkt.highest_layer}"
            self.packet_listbox.insert(tk.END, line)

        self.status_var.set(f"Extracted {len(omci_list)} OMCI packets")


    ############################################
    # View Packet
    ############################################
    def on_packet_select(self, event=None):
        sel = self.packet_listbox.curselection()
        if not sel:
            return

        idx = sel[0]
        pkt = self.packets[idx]

        # Try to print OMCI layer
        output = []
        output.append(str(pkt))
        try:
            output.append("\n--- OMCI Layer ---\n")
            output.append(str(pkt.omci))
        except:
            pass

        self.packet_display.delete("1.0", tk.END)
        self.packet_display.insert("1.0", "\n".join(output))


    ############################################
    # Regex Parser
    ############################################
    def parse_extracted_omci(self):
        if not self.packets:
            messagebox.showinfo("No Packets", "尚未載入或擷取 OMCI")
            return

        results = []
        for pkt in self.packets:
            try:
                t = str(pkt.omci)
            except:
                continue

            # 簡易示範 parser（你可換成你 v4.4 parser）
            me = re.findall(r"Message Type:\s*(.*)", t)
            entity = re.findall(r"Entity ID:\s*(.*)", t)

            results.append({
                "MessageType": me[0] if me else "",
                "EntityID": entity[0] if entity else "",
                "Raw": t,
            })

        self.decoded_packets = results
        messagebox.showinfo("解析完成", f"共解析 {len(results)} 筆 OMCI 封包")


    ############################################
    # Excel Export
    ############################################
    def export_excel(self):
        if not self.decoded_packets:
            messagebox.showwarning("No Data", "尚未解析 OMCI")
            return

        df = pd.DataFrame(self.decoded_packets)
        save_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel", "*.xlsx")]
        )
        if not save_path:
            return

        df.to_excel(save_path, index=False)
        messagebox.showinfo("Saved", f"Excel 已儲存：\n{save_path}")


    ############################################
    # ---- AI Placeholder（Part B 會加完整程式）----
    ############################################
    def ai_explain_current_omci(self):

        api_key = load_api_key()
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key

        """
        AI 解釋右側 packet_display 中的 OMCI decode
        """
        try:
            from openai import OpenAI
            client = OpenAI()
        except:
            messagebox.showerror("OpenAI 錯誤", "openai 套件未安裝，請執行：pip install openai")
            return

        omci_text = self.packet_display.get("1.0", tk.END).strip()
        if not omci_text:
            messagebox.showinfo("AI 解釋", "目前畫面沒有 OMCI 內容")
            return

        prompt = f"""
你是 OMCI / ITU-T G.988 專家。
以下內容是 OMCI 封包的 decode：

{omci_text}

請用「繁體中文」輸出 JSON：
{{
  "summary": "",
  "decoded_fields": [],
  "potential_issues": [],
  "suggestions": []
}}

請不要加入 ```，只輸出 JSON。
"""

        try:
            resp = client.responses.create(
                model="gpt-4.1-mini",
                input=[{"role": "user", "content": prompt}],
            )
            ai_text = resp.output_text
        except Exception as e:
            messagebox.showerror("AI Error", str(e))
            return

        # 顯示結果
        win = tk.Toplevel(self.root)
        win.title("AI 解釋 OMCI")
        win.geometry("900x700")

        txt = scrolledtext.ScrolledText(win, wrap="word", font=("Consolas", 11))
        txt.pack(expand=True, fill=tk.BOTH)
        txt.insert(tk.END, ai_text)


    def ai_summary_pcap(self):

        api_key = load_api_key()
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key

        """
        AI Summary 整檔 OMCI（採用抽樣 + 分批 + 避免 token 爆炸）
        """
        try:
            from openai import OpenAI
            client = OpenAI()
        except:
            messagebox.showerror("OpenAI Error", "請先安裝 openai")
            return

        if pyshark is None:
            messagebox.showerror("PyShark Missing", "請先 pip install pyshark")
            return

        pcap = filedialog.askopenfilename(
            title="選擇 PCAP/PCAPNG",
            filetypes=[("PCAP/PCAPNG", "*.pcap *.pcapng")]
        )
        if not pcap:
            return

        self.status_var.set("載入 OMCI 中…")
        self.root.update_idletasks()

        cap = pyshark.FileCapture(pcap, display_filter="omci")
        packets = [pkt for pkt in cap]
        cap.close()

        if not packets:
            messagebox.showinfo("沒有 OMCI", "PCAP 中沒有 OMCI 封包")
            return

        # 抽樣
        head_len = 200
        samples = []
        for idx, pkt in enumerate(packets):
            try:
                text = str(pkt.omci)[:head_len]
            except:
                continue
            samples.append({
                "index": idx + 1,
                "head": text
            })

        prompt = f"""
你是 OMCI / ITU-T G.988 專家。
以下是 OMCI 摘要樣本（每筆取前 200 字）：

{json.dumps(samples, ensure_ascii=False)}

請輸出 JSON：
{{
  "overall_summary": "",
  "me_statistics": [],
  "message_type_statistics": [],
  "potential_issues": [],
  "suggestions": [],
  "testcase_ideas": []
}}
只輸出 JSON，不要加入 ```。
"""

        self.status_var.set("AI 總結 PCAP 中…")
        self.root.update_idletasks()

        resp = client.responses.create(
            model="gpt-4.1-mini",
            input=[{"role": "user", "content": prompt}],
        )
        result = resp.output_text

        # 顯示視窗
        win = tk.Toplevel(self.root)
        win.title("AI Summary 整檔 OMCI")
        win.geometry("900x700")

        txt = scrolledtext.ScrolledText(win, wrap="word", font=("Consolas", 11))
        txt.pack(expand=True, fill=tk.BOTH)
        txt.insert(tk.END, result)

        # 自動存檔
        base = os.path.splitext(pcap)[0]
        txt_path = base + "_AI_OMCI_Summary.txt"
        md_path = base + "_AI_OMCI_Summary.md"

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(result)

        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# AI Summary (OMCI)\n\n" + result)

        self.status_var.set(f"AI Summary 完成，已輸出：{txt_path}, {md_path}")


    def ai_compare_parser_vs_wireshark(self):

        api_key = load_api_key()
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key

        """
        AI 比對：【Parser JSON/TXT】 vs 【Wireshark decode TXT】
        """
        from openai import OpenAI
        client = OpenAI()

        parser_file = filedialog.askopenfilename(
            title="選 Parser 解析（JSON 或 TXT）"
        )
        if not parser_file:
            return

        with open(parser_file, "r", encoding="utf-8") as f:
            parser_text = f.read()

        ws_file = filedialog.askopenfilename(
            title="選 Wireshark Decode TXT"
        )
        if not ws_file:
            return

        with open(ws_file, "r", encoding="utf-8") as f:
            ws_text = f.read()

        prompt = f"""
你是 OMCI / ITU-T G.988 專家。請比對以下兩份 OMCI 解析：

【Parser】
{parser_text}

【Wireshark】
{ws_text}

請輸出 JSON：
{{
  "overall_assessment": "",
  "fields_missing_in_parser": [],
  "fields_missing_in_wireshark": [],
  "conflicting_fields": [],
  "semantic_differences": [],
  "possible_root_causes": [],
  "suggestions_for_parser": [],
  "suggestions_for_tests": []
}}
只輸出 JSON。
"""

        resp = client.responses.create(
            model="gpt-4.1-mini",
            input=[{"role": "user", "content": prompt}],
        )

        result = resp.output_text

        # 顯示 GUI 視窗
        win = tk.Toplevel(self.root)
        win.title("AI 比對 Parser vs Wireshark")
        win.geometry("900x700")

        txt = scrolledtext.ScrolledText(win, wrap="word", font=("Consolas", 11))
        txt.pack(expand=True, fill=tk.BOTH)
        txt.insert(tk.END, result)

        # 自動存檔
        diff_path = os.path.splitext(parser_file)[0] + "_vs_ws_diff.txt"
        with open(diff_path, "w", encoding="utf-8") as f:
            f.write(result)

        self.status_var.set(f"AI 差異比對完成，已輸出：{diff_path}")


    def ai_generate_testcases_for_current_omci(self):

        api_key = load_api_key()
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key

        """
        基於畫面中 OMCI → 自動產生 TestRail 測項
        """
        from openai import OpenAI
        client = OpenAI()

        raw = self.packet_display.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showinfo("AI TestCase", "畫面沒有 OMCI 內容")
            return

        prompt = f"""
你是 GPON/XGSPON/25GPON OMCI 測試專家。
以下是 OMCI decode：

{raw}

請產生 6~12 筆 TestRail Test Case（繁體中文）：
JSON 格式如下：

{{
  "testcases": [
    {{
      "title": "",
      "objective": "",
      "steps": [],
      "expected_result": "",
      "priority": "P1/P2/P3"
    }}
  ]
}}

不要加入 ```，只輸出 JSON。
"""

        resp = client.responses.create(
            model="gpt-4.1",
            input=[{"role": "user", "content": prompt}],
        )

        result = resp.output_text

        win = tk.Toplevel(self.root)
        win.title("AI 產生 Test Cases")
        win.geometry("900x700")

        txt = scrolledtext.ScrolledText(win, wrap="word", font=("Consolas", 11))
        txt.pack(expand=True, fill=tk.BOTH)
        txt.insert(tk.END, result)


############################################
# Main
############################################
if __name__ == "__main__":
    root = tk.Tk()
    app = OMCIAnalyzerApp(root)
    root.mainloop()

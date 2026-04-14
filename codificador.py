# ═══════════════════════════════════════════════════════════════════════════════
# ENCRIPTADOR/DESENCRIPTADOR DE MENSAJES CON MATRICES
# Utiliza multiplicación matricial para cifrar y desencriptar textos
# ═══════════════════════════════════════════════════════════════════════════════

import tkinter as tk  # Librería para crear la interfaz gráfica
from tkinter import messagebox  # Para mostrar ventanas emergentes de error
import numpy as np  # Para operaciones matemáticas con matrices
from fractions import Fraction  # Para convertir decimales a fracciones

# ════════════════════════ PALETA DE COLORES ═══════════════════════════════════
# Define el esquema de colores del estilo "Matrix verde sobre fondo oscuro"
BG         = "#0a0a0f"  # Color de fondo principal (negro oscuro)
BG2        = "#0d150d"  # Color de fondo secundario (verde muy oscuro)
FG         = "#00ff41"  # Color de texto verde "Matrix" estándar
FG_DIM     = "#2a5a2a"  # Color de texto verde oscuro (etiquetas secundarias)
FG_BRIGHT  = "#39ff14"  # Color de texto verde brillante (títulos/mensajes)
ACCENT     = "#00cc33"  # Color de acento verde (bordes resaltados)
ENTRY_BG   = "#05100a"  # Color de fondo para campos de entrada
BTN_BG     = "#0a2a0a"  # Color de fondo de botones en estado normal
BTN_HOV    = "#0f3d0f"  # Color de fondo de botones al pasar el mouse
WARN       = "#ffaa00"  # Color de advertencia (naranja, usado en desencriptar)
WARN_DIM   = "#7a5000"  # Color de advertencia oscuro
ERR        = "#ff4444"  # Color de error (rojo)
BORDER     = "#004400"  # Color de bordes principales
BORDER2    = "#006600"  # Color de bordes secundarios
WHITE_FG   = "#ccffcc"  # Color de texto blanco suave
MONO       = "Courier New"  # Fuente monoespaciada para código

# ═══════════════════════════ DICCIONARIO ══════════════════════════════════════
# Mapeo de caracteres a números para la encriptación
# Cada carácter tiene un número único que será usado en la matriz
ENCODE = {
    # Letras mayúsculas: A=0, B=1, ..., Z=25
    "A": 0,  "B": 1,  "C": 2,  "D": 3,  "E": 4,  "F": 5,  "G": 6,  "H": 7,
    "I": 8,  "J": 9,  "K": 10, "L": 11, "M": 12, "N": 13, "O": 14, "P": 15,
    "Q": 16, "R": 17, "S": 18, "T": 19, "U": 20, "V": 21, "W": 22, "X": 23,
    "Y": 24, "Z": 25,
    # Letras minúsculas: a=26, b=27, ..., z=51
    "a": 26, "b": 27, "c": 28, "d": 29, "e": 30, "f": 31, "g": 32, "h": 33,
    "i": 34, "j": 35, "k": 36, "l": 37, "m": 38, "n": 39, "o": 40, "p": 41,
    "q": 42, "r": 43, "s": 44, "t": 45, "u": 46, "v": 47, "w": 48, "x": 49,
    "y": 50, "z": 51,
    # Dígitos: 0=52, 1=53, ..., 9=61
    "0": 52, "1": 53, "2": 54, "3": 55, "4": 56, "5": 57, "6": 58, "7": 59,
    "8": 60, "9": 61,
    # Símbolos especiales: espacio=62, !=63, "=64, etc.
    " ": 62, "!": 63, '"': 64,  "#": 65, "$": 66, "%": 67, "&": 68, "'": 69,
    "(": 70, ")": 71, "*": 72, "+": 73, ",": 74, "-": 75, ".": 76, "/": 77,
    ":": 78, ";": 79, "<": 80, "=": 81, ">": 82, "?": 83, "@": 84, "[": 85,
    "\\": 86, "]": 87, "^": 88, "_": 89, "`": 90, "{": 91, "|": 92, "}": 93,
    "~": 94, "Ñ": 95, "ñ": 96,  # Caracteres especiales españoles al final
}
# Diccionario inverso: números → caracteres (invierte el mapeo anterior)
DECODE = {v: k for k, v in ENCODE.items()}

# ══════════════════════════ CORE CRIPTOGRÁFICO ════════════════════════════════
# Funciones núcleo para encriptar y desencriptar mensajes usando matrices

def msg_to_matrix(text: str) -> np.ndarray:
    """Convierte texto → matriz 3×N (relleno columna-por-columna, padding con espacios)."""
    # Si el texto no es divisible entre 3, agregar espacios para completar
    while len(text) % 3:
        text += " "
    # Calcular el número de columnas necesarias (n = longitud total / 3)
    n = len(text) // 3
    # Crear matriz 3×N inicializada con ceros
    mat = np.zeros((3, n), dtype=float)
    # Llenar la matriz columna por columna
    for j in range(n):  # Para cada columna
        for i in range(3):  # Para cada fila (3 siempre)
            # Convertir el carácter a su número usando el diccionario ENCODE
            mat[i, j] = ENCODE[text[j * 3 + i]]
    return mat  # Retornar la matriz de números


def do_encrypt(text: str, key: np.ndarray) -> np.ndarray:
    """Encripta: multiplica la matriz clave (3×3) por la matriz del mensaje (3×N)."""
    # Operación: matriz_clave @ matriz_mensaje = matriz_encriptada
    return key @ msg_to_matrix(text)


def do_decrypt(enc: np.ndarray, key: np.ndarray) -> str:
    """Desencripta: calcula la inversa de la clave y la multiplica por la matriz encriptada."""
    # Calcular la matriz inversa de la clave
    inv_key = np.linalg.inv(key)
    # Multiplicar la inversa por los números encriptados y redondear a enteros
    nums = np.round(inv_key @ enc).astype(int)
    # Convertir los números nuevamente a caracteres usando el diccionario DECODE
    chars = [DECODE.get(int(nums[i, j]), "?")  # ? si el número no está en el diccionario
             for j in range(nums.shape[1])  # Para cada columna
             for i in range(3)]  # Para cada fila
    # Unir todos los caracteres en un string y eliminar espacios de relleno al final
    return "".join(chars).rstrip(" ")

# ════════════════════════ HELPERS DE WIDGETS ══════════════════════════════════

def mk_frame(parent, bg=BG, border_color=BORDER, **kw):
    kw.setdefault("highlightthickness", 1)
    kw.setdefault("highlightbackground", border_color)
    return tk.Frame(parent, bg=bg, **kw)


def mk_label(parent, text, size=10, bold=False, color=FG, bg=BG, **kw):
    return tk.Label(parent, text=text, bg=bg, fg=color,
                    font=(MONO, size, "bold" if bold else "normal"), **kw)


def mk_section_title(parent, text):
    row = tk.Frame(parent, bg=BG)
    tk.Label(row, text="▶ ", bg=BG, fg=ACCENT, font=(MONO, 10, "bold")).pack(side="left")
    tk.Label(row, text=text, bg=BG, fg=FG_BRIGHT, font=(MONO, 10, "bold")).pack(side="left")
    return row


def mk_entry(parent, width=7, fg=FG_BRIGHT, **kw):
    return tk.Entry(
        parent, width=width, bg=ENTRY_BG, fg=fg,
        insertbackground=FG, relief="flat",
        font=(MONO, 11), justify="center",
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        **kw,
    )


def mk_button(parent, text, cmd, fg=FG_BRIGHT, border=None, **kw):
    """Crear un Botón personalizado con efectos de hover (pasar mouse)."""
    kw.setdefault("padx", 22)  # Espaciado horizontal dentro del botón
    kw.setdefault("pady", 10)  # Espaciado vertical dentro del botón
    b = tk.Button(
        parent, text=text, command=cmd,  # Texto del botón y función al hacer clic
        bg=BTN_BG, fg=fg,  # Colores de botón y texto
        activebackground=BTN_HOV, activeforeground=fg,  # Colores cuando se hace clic
        relief="flat", cursor="hand2",  # Sin borde 3D, cursor de mano
        font=(MONO, 12, "bold"),  # Fuente grande y negrita
        highlightthickness=2,  # Grosor del borde resaltado
        highlightbackground=border or fg,  # Color del borde
        **kw,
    )
    # Cambiar color cuando el ratón entra al botón (efecto hover)
    b.bind("<Enter>", lambda e: b.config(bg=BTN_HOV))
    # Cambiar color cuando el ratón sale del botón
    b.bind("<Leave>", lambda e: b.config(bg=BTN_BG))
    return b  # Retornar el botón creado


def parse_3x3(entries) -> np.ndarray:
    """Leer una matriz 3×3 desde campos de entrada y convertirla a números."""
    mat = np.zeros((3, 3), dtype=float)  # Crear matriz 3×3 con ceros
    for i in range(3):  # Para cada fila
        for j in range(3):  # Para cada columna
            v = entries[i][j].get().strip()  # Obtener valor de la entrada y eliminar espacios
            if not v:  # Si la entrada está vacía, lanzar error
                raise ValueError(f"Matriz codificadora: celda [{i+1},{j+1}] está vacía.")
            mat[i, j] = float(v)  # Convertir el valor a número decimal
    return mat  # Retornar la matriz 3×3


def _fmt_matrix(mat: np.ndarray, decimals: int = 2, integers: bool = False, fractions: bool = False) -> str:
    """Formatea una matriz numpy como tabla de texto para mostrar en pantalla.
    
    Parámetros:
    - mat: matriz a formatear
    - decimals: número de decimales si se muestran como floats
    - integers: si True, muestra como enteros
    - fractions: si True, muestra como fracciones
    """
    rows, cols = mat.shape
    lines = []
    for i in range(rows):
        cells = []
        for j in range(cols):
            if fractions:
                # Convertir a fracción con límite de denominador
                frac = Fraction(mat[i, j]).limit_denominator(1000)
                cells.append(f"{str(frac):>10}")
            elif integers:
                cells.append(f"{round(mat[i, j]):>8}")
            else:
                cells.append(f"{mat[i, j]:>10.{decimals}f}")
        lines.append("  │  " + "   ".join(cells) + "  │")
    return "\n".join(lines)


def build_entry_grid(parent, rows, cols, width=8):
    """Crear y devolver una grilla (grid) de campos de entrada (Entry widgets)."""
    grid = []  # Lista para almacenar todas las filas
    # Crear encabezados de columnas (C1, C2, C3, ...)
    tk.Label(parent, text="", bg=BG, font=(MONO, 8)).grid(row=0, column=0)  # Esquina vacía
    for j in range(cols):  # Para cada columna
        mk_label(parent, f"C{j+1}", size=8, color=FG_DIM, bg=BG).grid(
            row=0, column=j + 1, padx=2)  # Etiqueta de la columna
    
    # Crear filas de campos de entrada
    for i in range(rows):  # Para cada fila
        mk_label(parent, f"F{i+1}", size=8, color=FG_DIM, bg=BG).grid(
            row=i + 1, column=0, padx=6, pady=1)  # Etiqueta de la fila
        row_widgets = []  # Lista para los campos de esta fila
        for j in range(cols):  # Para cada columna
            e = mk_entry(parent, width=width)  # Crear un campo de entrada
            e.grid(row=i + 1, column=j + 1, padx=2, pady=2)  # Posicionar en la grilla
            row_widgets.append(e)  # Agregar el campo a la lista de la fila
        grid.append(row_widgets)  # Agregar la fila completa a la grilla
    return grid  # Retornar toda la grilla


def separator(parent, color=BORDER2):
    tk.Frame(parent, bg=color, height=1).pack(fill="x", padx=12, pady=4)


# ══════════════════════════ VENTANA 1: ENCRIPTAR ══════════════════════════════
# Ventana para encriptar un mensaje usando multiplicación de matrices

class EncryptWindow(tk.Toplevel):
    """Ventana secundaria para encriptar mensajes."""

    def __init__(self, master):
        # Inicializar como ventana secundaria (Toplevel)
        super().__init__(master)
        self.title("ENCRIPTAR MENSAJE")  # Título de la ventana
        self.config(bg=BG)  # Color de fondo
        self.resizable(True, True)  # Permitir redimensionar la ventana
        self.minsize(580, 950)  # Tamaño mínimo de la ventana (aumentado para mejor visualización)
        self._build()  # Construir la interfaz gráfica

    # ── Construcción de la interfaz ───────────────────────────────────────────
    def _build(self):
        """Construir todos los elementos de la interfaz gráfica."""
        P = dict(padx=14, pady=5)  # Variables de espaciado comunes

        # ═ SECCIÓN: CABECERA ═════════════════════════════════════════════════════
        header = tk.Frame(self, bg=BG2, highlightthickness=1,
                          highlightbackground=ACCENT)  # Marco con borde
        header.pack(fill="x", padx=12, pady=(14, 6))  # Llenar horizontalmente
        mk_label(header, "ENCRIPTADOR DE MENSAJES",
                 size=13, bold=True, color=FG_BRIGHT, bg=BG2).pack(pady=(10, 2))  # Título
        mk_label(header, "  Multiplicación Matricial — Clave 3×3  ",
                 size=9, color=FG_DIM, bg=BG2).pack(pady=(0, 10))  # Subtítulo

        # ═ SECCIÓN: MENSAJE DE ENTRADA ═══════════════════════════════════════════
        f1 = mk_frame(self)  # Crear marco para esta sección
        f1.pack(fill="x", **P)
        mk_section_title(f1, "MENSAJE A ENCRIPTAR").pack(anchor="w", padx=8, pady=(8, 4))
        # Campo de texto multi-línea para el mensaje
        self.txt_msg = tk.Text(
            f1, height=4, width=54, wrap="word",  # 4 líneas de alto
            bg=ENTRY_BG, fg=FG_BRIGHT, insertbackground=FG,  # Colores
            relief="flat", font=(MONO, 11),  # Fuente monoespaciada
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT,
        )
        self.txt_msg.pack(padx=10, pady=(0, 10))

        # ═ SECCIÓN: MATRIZ CODIFICADORA ═════════════════════════════════════════
        f2 = mk_frame(self)  # Crear marco para esta sección
        f2.pack(fill="x", **P)
        mk_section_title(f2, "MATRIZ CODIFICADORA  (3 × 3)").pack(
            anchor="w", padx=8, pady=(8, 4))
        fg = tk.Frame(f2, bg=BG)  # Sub-marco para la grilla de entrada
        fg.pack(padx=10, pady=(0, 10))
        
        # Crear encabezados de columnas
        for j in range(3):
            mk_label(fg, f"  C{j+1}", size=9, color=FG_DIM).grid(
                row=0, column=j + 1, padx=2)
        
        # Crear grilla 3×3 de campos para la matriz
        self.key_e = []  # Lista para almacenar los campos
        for i in range(3):  # Para cada fila
            mk_label(fg, f"F{i+1}", size=9, color=FG_DIM).grid(
                row=i + 1, column=0, padx=6)  # Etiqueta de fila
            row = []  # Lista para esta fila
            for j in range(3):  # Para cada columna
                e = mk_entry(fg, width=8)  # Crear campo
                e.grid(row=i + 1, column=j + 1, padx=4, pady=3)  # Posicionar
                row.append(e)  # Agregar a la fila
            self.key_e.append(row)  # Agregar fila a la matriz

        # ═ SECCIÓN: BOTÓN ENCRIPTAR ==============================================
        separator(self)  # Línea separadora
        btn = mk_button(self, " ENCRIPTAR MENSAJE", self._run,
                        fg=FG_BRIGHT, border=ACCENT, padx=36, pady=12)
        btn.pack(pady=8)
        separator(self)

        # ═ SECCIÓN: RESULTADO (MATRIZ ENCRIPTADA) =====================================
        f3 = mk_frame(self)  # Marco para resultado
        f3.pack(fill="both", expand=True, **P)  # Llenar espacio disponible
        mk_section_title(f3, "MATRIZ ENCRIPTADA").pack(
            anchor="w", padx=8, pady=(8, 4))

        # Campo de texto para mostrar la matriz encriptada
        self.result_txt = tk.Text(
            f3, wrap="none", height=10,
            bg=ENTRY_BG, fg=WARN,  # Color de advertencia (naranja)
            relief="flat", font=(MONO, 10),
            highlightthickness=1, highlightbackground=BORDER,
            state="disabled",  # No se puede editar directamente
        )
        self.result_txt.pack(fill="both", expand=True, padx=10, pady=(0, 2))
        
        # Barra de desplazamiento horizontal para números largos
        sb_x = tk.Scrollbar(f3, orient="horizontal",
                            command=self.result_txt.xview,
                            bg=BG, troughcolor=BG2)
        self.result_txt.config(xscrollcommand=sb_x.set)  # Conectar barra al texto
        sb_x.pack(fill="x", padx=10, pady=(0, 8))

        # ═ SECCIÓN: PASO A PASO ═══════════════════════════════════════════════
        separator(self)
        f4 = mk_frame(self, border_color=ACCENT)
        f4.pack(fill="both", expand=True, padx=14, pady=5)  # Expandir para ocupar espacio disponible
        mk_section_title(f4, "PASO A PASO — Operaciones matriciales").pack(
            anchor="w", padx=8, pady=(8, 4))

        # Widget de texto con doble scroll para mostrar los pasos
        steps_frame = tk.Frame(f4, bg=BG)
        steps_frame.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        # Barra de desplazamiento vertical (principal)
        sb_steps_y = tk.Scrollbar(steps_frame, orient="vertical", bg=BG, troughcolor=BG2)
        # Barra de desplazamiento horizontal (para líneas largas)
        sb_steps_x = tk.Scrollbar(steps_frame, orient="horizontal", bg=BG, troughcolor=BG2)

        # Widget de texto sin límite de altura (se ajusta automáticamente)
        self.steps_txt = tk.Text(
            steps_frame, wrap="none",
            bg="#030d03", fg=FG,
            relief="flat", font=(MONO, 9),
            highlightthickness=1, highlightbackground=BORDER,
            state="disabled",
            xscrollcommand=sb_steps_x.set,
            yscrollcommand=sb_steps_y.set,
        )
        sb_steps_y.config(command=self.steps_txt.yview)
        sb_steps_x.config(command=self.steps_txt.xview)

        # Distribuir barras y texto en la grilla
        sb_steps_y.pack(side="right", fill="y")
        sb_steps_x.pack(side="bottom", fill="x")
        self.steps_txt.pack(fill="both", expand=True)  # El texto se expande para llenar el espacio

        # Configurar colores de etiquetas para resaltar diferentes secciones
        self.steps_txt.tag_configure("title",   foreground=FG_BRIGHT, font=(MONO, 9, "bold"))
        self.steps_txt.tag_configure("step",    foreground=ACCENT,    font=(MONO, 9, "bold"))
        self.steps_txt.tag_configure("matrix",  foreground="#aaffaa", font=(MONO, 9))
        self.steps_txt.tag_configure("inv",     foreground=WARN,      font=(MONO, 9))
        self.steps_txt.tag_configure("calc",    foreground=WHITE_FG,  font=(MONO, 9))
        self.steps_txt.tag_configure("result",  foreground=WARN,      font=(MONO, 9, "bold"))
        self.steps_txt.tag_configure("sep",     foreground=FG_DIM,    font=(MONO, 9))

        # Mensaje inicial antes de encriptar
        self.steps_txt.config(state="normal")
        self.steps_txt.insert("end",
            "\n  Presiona  [ ENCRIPTAR MENSAJE ]  para ver el proceso paso a paso...\n",
            "sep")
        self.steps_txt.config(state="disabled")


    # ── Lógica de encriptación ────────────────────────────────────────────────
    def _run(self):
        """Ejecutar el proceso de encriptación cuando se presiona el botón."""
        try:
            # Obtener el texto desde el widget Text (desde línea 1 hasta el final sin última línea)
            text = self.txt_msg.get("1.0", "end-1c")
            # Validar que el mensaje no esté vacío
            if not text:
                raise ValueError("El mensaje está vacío.")
            # Buscar caracteres que no estén en el diccionario ENCODE
            unsupported = [ch for ch in text if ch not in ENCODE]
            # Si hay caracteres no soportados, mostrar error
            if unsupported:
                raise ValueError(
                    f"Carácter(es) no soportado(s): {set(unsupported)}\n"
                    "El programa soporta letras A-Z, a-z, 0-9, espacios y símbolos comunes."
                )
            # Obtener la matriz clave desde los campos de entrada
            key = parse_3x3(self.key_e)
            # Calcular el determinante de la matriz
            det = np.linalg.det(key)
            # Si el determinante es casi cero, la matriz no tiene inversa (se necesita para desencriptar)
            if abs(det) < 1e-9:
                raise ValueError(
                    f"La matriz codificadora NO tiene inversa (det ≈ {det:.6f}).\n"
                    "Por favor elige una matriz con determinante ≠ 0."
                )
            # Encriptar el texto usando la matriz
            enc = do_encrypt(text, key)
            # Capturar también la matriz del mensaje para el paso a paso
            padded = text
            while len(padded) % 3:
                padded += " "
            msg_mat = msg_to_matrix(text)
            # Mostrar el resultado en la ventana
            self._display(enc)
            # Mostrar el proceso paso a paso
            self._display_steps(padded, key, msg_mat, enc)
        # Si hay un error, mostrar una ventana emergente
        except ValueError as exc:
            messagebox.showerror("Error de Encriptación", str(exc), parent=self)

    def _display(self, enc: np.ndarray):
        """Mostrar la matriz encriptada en un formato tabla para que el usuario la pueda ver."""
        _, cols = enc.shape  # Obtener el número de columnas
        lines = []  # Lista para almacenar las líneas de texto
        # Agregar línea de información sobre las dimensiones
        lines.append(f"  Dimensiones: 3 × {cols}   (valores redondeados al entero)\n")

        # Crear encabezado de la tabla con nombres de columnas
        header_row = "         " + "".join(f"  {'Col'+str(j+1):>7}" for j in range(cols))
        lines.append(header_row)  # Agregar encabezado
        lines.append("         " + "─" * (cols * 9 + 4))  # Línea divisoria

        # Mostrar cada fila de la matriz encriptada redondeada a enteros
        for i in range(3):
            row_s = f"  Fila {i+1}  │" + "".join(
                f"  {round(enc[i, j]):>7}" for j in range(cols))  # Redondear a entero
            lines.append(row_s)

        # Sección con los valores enteros listos para copiar
        lines.append("")
        lines.append("  ── Valores enteros (copiar a Ventana 2) ──────────────────")
        for i in range(3):
            lines.append("  " + "   ".join(f"{round(enc[i, j]):>9}" for j in range(cols)))
        
        # Agregar el determinante como información adicional
        lines.append("")
        lines.append(f"  Determinante de la clave: {np.linalg.det(parse_3x3(self.key_e)):.4f}")

        # Mostrar el resultado en el widget de texto deshabilitado
        self.result_txt.config(state="normal")  # Habilitar para escribir
        self.result_txt.delete("1.0", "end")  # Limpiar contenido anterior
        self.result_txt.insert("end", "\n".join(lines))  # Insertar nuevas líneas
        self.result_txt.config(state="disabled")  # Deshabilitar para que no se edite

    def _display_steps(self, padded_text: str, key: np.ndarray,
                       msg_mat: np.ndarray, enc: np.ndarray):
        """Muestra el proceso completo paso a paso en el widget de pasos."""
        _, cols = msg_mat.shape
        inv_key = np.linalg.inv(key)
        det = np.linalg.det(key)

        # ─── Helpers internos ────────────────────────────────────────────────
        def ins(text, tag=""):
            """Insertar texto con tag opcional."""
            if tag:
                self.steps_txt.insert("end", text, tag)
            else:
                self.steps_txt.insert("end", text)

        def line(text="", tag=""):
            ins(text + "\n", tag)

        SEP  = "  " + "═" * 68
        SEP2 = "  " + "─" * 68

        # ─── Preparar widget ─────────────────────────────────────────────────
        self.steps_txt.config(state="normal")
        self.steps_txt.delete("1.0", "end")

        # ══ ENCABEZADO ════════════════════════════════════════════════════════
        line(SEP, "sep")
        line("  PROCESO DE ENCRIPTACIÓN — PASO A PASO", "title")
        line(SEP, "sep")
        line()

        # ══ PASO 1: Conversión texto → números ════════════════════════════════
        line("  PASO 1 ── Conversión del mensaje en números", "step")
        line(SEP2, "sep")
        line("  Cada carácter se convierte usando el diccionario ENCODE:", "calc")
        line()
        chunk = 8
        for start in range(0, len(padded_text), chunk):
            segment = padded_text[start:start + chunk]
            row_parts = []
            for ch in segment:
                label = "SPC" if ch == " " else repr(ch).strip("'")
                row_parts.append(f" {label:>3}={ENCODE[ch]:<3}")
            ins("  " + "  ".join(row_parts) + "\n", "calc")
        line()

        # ══ PASO 2: Matriz del mensaje ════════════════════════════════════════
        line(f"  PASO 2 ── Matriz del Mensaje  [M]  (3 × {cols})", "step")
        line(SEP2, "sep")
        line("  Los números se agrupan en columnas de 3 (una columna = 3 caracteres):", "calc")
        line()
        line(_fmt_matrix(msg_mat, integers=True), "matrix")
        line()

        # ══ PASO 3: Matriz codificadora ═══════════════════════════════════════
        line("  PASO 3 ── Matriz Codificadora  [K]  (3 × 3)", "step")
        line(SEP2, "sep")
        line("  Esta es la clave secreta usada para cifrar:", "calc")
        line()
        line(_fmt_matrix(key, fractions=True), "matrix")
        line(f"\n  Determinante de [K]  =  {det:.6f}", "calc")
        line()

        # ══ PASO 4: Inversa de K ══════════════════════════════════════════════
        line("  PASO 4 ── Inversa de la Clave  [K⁻¹]  (se usará al DESENCRIPTAR)", "step")
        line(SEP2, "sep")
        line("  Para desencriptar se necesita que  [K⁻¹] × [K] = Identidad:", "calc")
        line()
        line(_fmt_matrix(inv_key, fractions=True), "inv")
        line()
        # Verificación K⁻¹ × K ≈ I
        identity_check = np.round(inv_key @ key, 4)
        line("  Verificación  [K⁻¹] × [K]  ≈  Identidad:", "calc")
        line(_fmt_matrix(identity_check, fractions=True), "inv")
        line()

        # ══ PASO 5: Multiplicación columna por columna ═════════════════════════
        line("  PASO 5 ── Multiplicación  [K] × [M]  =  [E]  (columna por columna)", "step")
        line(SEP2, "sep")
        line("  Cada columna de [E] = [K] × (columna de [M]):", "calc")
        line()

        show_cols = min(cols, 5)   # Mostrar detalle de hasta 5 columnas
        row_labels = ["F1", "F2", "F3"]
        for j in range(show_cols):
            col_vals = [int(msg_mat[r, j]) for r in range(3)]
            ins(f"  ┌── Columna {j+1}  →  M[:,{j+1}] = ", "step")
            ins(f"[{col_vals[0]}, {col_vals[1]}, {col_vals[2]}]ᵀ\n", "matrix")
            for i in range(3):
                # Mostrar la clave como fracciones
                terms = "  +  ".join(
                    f"{Fraction(key[i,k]).limit_denominator(1000):>6} × {int(msg_mat[k,j]):>4}"
                    for k in range(3)
                )
                result_val = round(enc[i, j])
                ins(f"  │  E[{row_labels[i]},{j+1}] = {terms}  =  ", "calc")
                ins(f"{result_val}\n", "result")
            line()

        if cols > show_cols:
            line(f"  ... (detalle de las primeras {show_cols} de {cols} columnas)", "sep")
            line()

        # ══ PASO 6: Matriz encriptada final ════════════════════════════════════
        line(f"  PASO 6 ── Resultado Final: Matriz Encriptada  [E]  (3 × {cols})", "step")
        line(SEP2, "sep")
        line("  Esta es la matriz que se pasa a la ventana de DESENCRIPTAR:", "calc")
        line()
        line(_fmt_matrix(enc, integers=True), "result")
        line()
        line(SEP, "sep")
        line("  ✔  Proceso completado. Copia los valores a la ventana de Desencriptar.", "title")
        line(SEP, "sep")

        self.steps_txt.config(state="disabled")
        self.steps_txt.see("1.0")   # Volver al inicio


# ══════════════════════════ VENTANA 2: DESENCRIPTAR ═══════════════════════════
# Ventana para desencriptar mensajes que fueron previamente encriptados

class DecryptWindow(tk.Toplevel):
    """Ventana secundaria para desencriptar mensajes."""

    def __init__(self, master):
        # Inicializar como ventana secundaria (Toplevel)
        super().__init__(master)
        self.title("DESENCRIPTAR MENSAJE")  # Título de la ventana
        self.config(bg=BG)  # Color de fondo
        self.resizable(True, True)  # Permitir redimensionar
        self.minsize(560, 720)  # Tamaño mínimo
        self._enc_grid = []  # Lista para almacenar los campos de la matriz encriptada
        self._build()  # Construir la interfaz

    # ── Construcción de la interfaz ───────────────────────────────────────────
    def _build(self):
        """Construir todos los elementos de la interfaz gráfica para desencriptar."""
        P = dict(padx=14, pady=5)  # Variables de espaciado comunes

        # ═ SECCIÓN: CABECERA ═════════════════════════════════════════════════════
        header = tk.Frame(self, bg=BG2, highlightthickness=1,
                          highlightbackground=WARN)  # Marco con borde
        header.pack(fill="x", padx=12, pady=(14, 6))
        mk_label(header, "DESENCRIPTADOR DE MENSAJES",
                 size=13, bold=True, color=WARN, bg=BG2).pack(pady=(10, 2))  # Título
        mk_label(header, "  Matriz Inversa × Matriz Encriptada  ",
                 size=9, color=WARN_DIM, bg=BG2).pack(pady=(0, 10))  # Subtítulo

        # ═ SECCIÓN: DIMENSIONES DE LA MATRIZ =================================
        f0 = mk_frame(self, border_color=WARN_DIM)  # Marco con borde
        f0.pack(fill="x", **P)
        mk_section_title(f0, "DIMENSIONES DE LA MATRIZ ENCRIPTADA").pack(
            anchor="w", padx=8, pady=(8, 4))
        fs = tk.Frame(f0, bg=BG)  # Marco para los controles
        fs.pack(anchor="w", padx=12, pady=(0, 10))
        
        # Etiqueta para filas (siempre 3)
        mk_label(fs, "Filas (fijo): ", size=10, color=FG).pack(side="left")
        mk_label(fs, "3", size=11, bold=True, color=FG_BRIGHT).pack(side="left")
        
        # Selector de columnas (número de columnas de la matriz encriptada)
        mk_label(fs, "    Columnas:", size=10, color=FG).pack(side="left", padx=(16, 4))
        self.cols_var = tk.IntVar(value=3)  # Variable para almacenar número de columnas
        spin = tk.Spinbox(
            fs, from_=1, to=99, textvariable=self.cols_var,  # Selector numérico (1-99)
            width=4, bg=ENTRY_BG, fg=FG_BRIGHT,  # Estilos
            buttonbackground=BTN_BG, relief="flat",
            font=(MONO, 12, "bold"), justify="center",
        )
        spin.pack(side="left", padx=4)
        
        # Botón para generar la grilla dinámicamente
        mk_button(fs, "↺ GENERAR GRILLA", self._rebuild_enc_grid,
                  fg=ACCENT, border=BORDER2, padx=12, pady=6).pack(
                      side="left", padx=12)
        # ═ SECCIÓN: MATRIZ CODIFICADORA ═════════════════════════════════════════
        f1 = mk_frame(self, border_color=WARN_DIM)  # Marco con borde
        f1.pack(fill="x", **P)
        mk_section_title(f1, "MATRIZ CODIFICADORA  (3 × 3)").pack(
            anchor="w", padx=8, pady=(8, 4))
        fkg = tk.Frame(f1, bg=BG)  # Sub-marco para la grilla
        fkg.pack(padx=10, pady=(0, 10))
        
        # Crear encabezados de columnas
        for j in range(3):
            mk_label(fkg, f"  C{j+1}", size=9, color=FG_DIM).grid(
                row=0, column=j + 1, padx=2)
        
        # Crear grilla 3×3 para la matriz codificadora
        self.key_e = []  # Lista para almacenar los campos
        for i in range(3):  # Para cada fila
            mk_label(fkg, f"F{i+1}", size=9, color=FG_DIM).grid(
                row=i + 1, column=0, padx=6)  # Etiqueta de fila
            row = []  # Lista para esta fila
            for j in range(3):  # Para cada columna
                e = mk_entry(fkg, width=8)  # Campo de entrada
                e.grid(row=i + 1, column=j + 1, padx=4, pady=3)  # Posicionar
                row.append(e)  # Agregar a la fila
            self.key_e.append(row)  # Agregar fila a la matriz

        # ═ SECCIÓN: MATRIZ ENCRIPTADA ═══════════════════════════════════════════
        f2 = mk_frame(self, border_color=WARN_DIM)  # Marco con borde
        f2.pack(fill="x", **P)
        mk_section_title(f2, "MATRIZ ENCRIPTADA  (3 × N)").pack(
            anchor="w", padx=8, pady=(8, 4))

        # Crear un Canvas scrollable horizontalmente (para grillas muy amplias)
        self._enc_canvas = tk.Canvas(
            f2, bg=BG, height=130, highlightthickness=0)  # Canvas vacío
        self._enc_hbar = tk.Scrollbar(
            f2, orient="horizontal",  # Barra de desplazamiento horizontal
            command=self._enc_canvas.xview,  # Conectar barra al canvas
            bg=BG, troughcolor=BG2)
        self._enc_canvas.config(xscrollcommand=self._enc_hbar.set)  # Conectar canvas a barra
        self._enc_hbar.pack(side="bottom", fill="x", padx=10)
        self._enc_canvas.pack(fill="x", padx=10, pady=(0, 4))

        # Marco interior donde se colocará la grilla (puede ser más ancho que el canvas)
        self._enc_inner = tk.Frame(self._enc_canvas, bg=BG)
        self._enc_inner_id = self._enc_canvas.create_window(
            (0, 0), window=self._enc_inner, anchor="nw")  # Insertar marco en el canvas
        # Cuando el marco se redimensiona, actualizar la región scrollable del canvas
        self._enc_inner.bind(
            "<Configure>",
            lambda e: self._enc_canvas.config(
                scrollregion=self._enc_canvas.bbox("all")))

        # Crear la grilla inicial con 3 columnas
        self._rebuild_enc_grid()
        # ═ SECCIÓN: BOTÓN DESENCRIPTAR ==========================================
        separator(self)  # Línea separadora
        btn = mk_button(self, "DESENCRIPTAR", self._run,
                        fg=WARN, border=WARN, padx=36, pady=12)  # Botón principal
        btn.pack(pady=8)
        separator(self)  # Línea separadora

        # ═ SECCIÓN: RESULTADO (MENSAJE DESENCRIPTADO) ===========================
        f3 = mk_frame(self, border_color=WARN_DIM)  # Marco para resultado
        f3.pack(fill="x", **P)
        mk_section_title(f3, "MENSAJE DESENCRIPTADO").pack(
            anchor="w", padx=8, pady=(8, 4))
        
        # Variable para almacenar el resultado
        self._res_var = tk.StringVar(value="")
        # Campo de entrada de solo lectura para mostrar el resultado
        res_e = tk.Entry(
            f3, textvariable=self._res_var, state="readonly",  # No se puede editar
            readonlybackground=ENTRY_BG, fg=FG_BRIGHT,  # Colores
            font=(MONO, 13), relief="flat", width=50,  # Fuente grande
            highlightthickness=1, highlightbackground=BORDER,
        )
        res_e.pack(padx=10, pady=(0, 10), fill="x")

        # Tip útil para el usuario
        mk_label(self, "  Tip: los espacios de relleno al final son eliminados automáticamente  ",
                 size=8, color=FG_DIM).pack(pady=(0, 10))

    # ── Reconstruir grilla de matriz encriptada ───────────────────────────────
    def _rebuild_enc_grid(self):
        """Limpiar y reconstruir la grilla de matriz encriptada (número de columnas dinámico)."""
        # Eliminar todos los widgets hijos del marco interior
        for w in self._enc_inner.winfo_children():
            w.destroy()
        
        # Reinicializar la lista de campos
        self._enc_grid = []
        # Obtener el número de columnas desde el Spinbox
        cols = self.cols_var.get()
        # Crear la grilla en el marco interior (3 filas × cols columnas)
        build_entry_grid(self._enc_inner, 3, cols, width=10)
        
        # Extraer los widgets de tipo Entry creados en la grilla
        children = self._enc_inner.grid_slaves()
        # Diccionario para mapear (fila, columna) a su widget
        entry_map = {}
        for w in children:
            info = w.grid_info()  # Obtener información de grid de cada widget
            r, c = int(info["row"]), int(info["column"])  # Obtener fila y columna
            if r >= 1 and c >= 1 and isinstance(w, tk.Entry):  # Solo Entry widgets en datos
                entry_map[(r - 1, c - 1)] = w  # Mapear con índices desde 0
        
        # Reconstruir la grilla de campos agrupados por filas
        for i in range(3):  # Para cada fila
            row = [entry_map[(i, j)] for j in range(cols)]  # Obtener campos de esta fila
            self._enc_grid.append(row)  # Agregar fila a la grilla

    # ── Lógica de desencriptación ─────────────────────────────────────────────
    def _run(self):
        """Ejecutar el proceso de desencriptación cuando se presiona el botón."""
        try:
            # Obtener la matriz clave desde los campos de entrada
            key = parse_3x3(self.key_e)
            # Calcular el determinante de la matriz clave
            det = np.linalg.det(key)
            # Si el determinante es casi cero, la matriz no tiene inversa
            if abs(det) < 1e-9:
                raise ValueError(
                    f"La matriz codificadora NO tiene inversa (det ≈ {det:.6f}).\n"
                    "Verifica la matriz e inténtalo de nuevo."
                )
            
            # Obtener el número de columnas especificado por el usuario
            cols = self.cols_var.get()
            # Validar que la grilla actual coincida con el número de columnas
            if not self._enc_grid or len(self._enc_grid[0]) != cols:
                raise ValueError(
                    "La grilla no coincide con el número de columnas.\n"
                    "Presiona '↺ GENERAR GRILLA' y luego vuelve a ingresar los datos."
                )
            
            # Crear matriz 3×cols para los números encriptados
            enc = np.zeros((3, cols), dtype=float)
            # Leer todos los valores de la grilla
            for i in range(3):  # Para cada fila
                for j in range(cols):  # Para cada columna
                    v = self._enc_grid[i][j].get().strip()  # Obtener valor
                    if not v:  # Validar que no esté vacío
                        raise ValueError(
                            f"Matriz encriptada: celda [{i+1},{j+1}] está vacía.")
                    enc[i, j] = float(v)  # Convertir a número decimal
            
            # Desencriptar usando la matriz clave y la matriz encriptada
            msg = do_decrypt(enc, key)
            # Mostrar el mensaje desencriptado en el campo de resultado
            self._res_var.set(msg)
        # Si hay un error, mostrar una ventana emergente
        except ValueError as exc:
            messagebox.showerror("Error de Desencriptación", str(exc), parent=self)


# ══════════════════════════ VENTANA PRINCIPAL ══════════════════════════════════
# Ventana principal que permite elegir entre encriptar o desencriptar

class MatrixCipher(tk.Tk):
    """Ventana principal de la aplicación."""

    def __init__(self):
        # Inicializar como ventana principal (Tk)
        super().__init__()
        self.title("MATRIX CIPHER")  # Título de la ventana
        self.config(bg=BG)  # Color de fondo
        self.resizable(False, False)  # No permitir redimensionar
        self._build()  # Construir la interfaz

    def _build(self):
        """Construir la interfaz gráfica de la ventana principal."""
        # ═ SECCIÓN: BANNER (ARTE ASCII) ================================================
        # Crear un arte ASCII decorativo para la ventana principal
        banner_lines = [
            "",
            "  ╔═══════════════════════════════════════╗",
            "  ║                                       ║",
            "  ║           DESENCRIPTADOR              ║",
            "  ║                                       ║",
            "  ║    Cifrado por Multiplicación         ║",
            "  ║    de Matrices con Inversa            ║",
            "  ║                                       ║",
            "  ╚═══════════════════════════════════════╝",
            "",
        ]
        # Unir todas las líneas en un string de una sola línea
        banner_text = "\n".join(banner_lines)
        # Mostrar el banner como una etiqueta
        tk.Label(
            self, text=banner_text, bg=BG, fg=FG_BRIGHT,
            font=(MONO, 11, "bold"), justify="left",  # Fuente monoespaciada, justificado a izquierda
        ).pack(pady=(14, 4))

        # ═ SECCIÓN: SUBTÍTULO ANIMADO ==================================================
        # Variable que contendrá el texto del subtítulo (cambiará durante la animación)
        self._sub_var = tk.StringVar(value="")
        # Etiqueta que muestra el subtítulo
        tk.Label(
            self, textvariable=self._sub_var,  # Mostrar el contenido de _sub_var
            bg=BG, fg=FG_DIM, font=(MONO, 9),
        ).pack(pady=(0, 6))
        # Iniciar la animación de escritura progresiva (typing effect)
        self._animate_sub("  [ Sistema de encriptación — UMES 2026 ]  ")

        # ═ SECCIÓN: ESTADÍSTICAS DEL DICCIONARIO ====================================
        # Crear un marco informativo mostrando qué caracteres soporta el programa
        info_frame = tk.Frame(self, bg=BG2, highlightthickness=1,
                              highlightbackground=BORDER)  # Marco con borde
        info_frame.pack(padx=22, pady=8, fill="x")  # Llenar horizontalmente
        # Crear un string con estadísticas del diccionario
        stats = (
            f"  Letras: 52   Dígitos: 10   Símbolos: 34   "
            f"Especiales: 1 (Ñ/ñ)  "
        )
        mk_label(info_frame, stats, size=8, color=FG_DIM, bg=BG2).pack(pady=6)

        # ═ SECCIÓN: BOTONES PRINCIPALES ================================================
        # Crear un marco contenedor para los dos botones principales
        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(padx=22, pady=20)

        # ─ BOTÓN 1: ENCRIPTAR ────────────────────────────────────────────────────
        b_enc = tk.Button(
            btn_frame,
            # Texto con instrucciones paso a paso
            text="ENCRIPTAR\n\n◆ Ingresa mensaje\n◆ Define matriz 3×3\n◆ Obtén matriz cifrada",
            command=lambda: EncryptWindow(self),  # Abrir ventana de encriptación
            bg=BTN_BG, fg=FG_BRIGHT,  # Colores normales
            activebackground=BTN_HOV, activeforeground=FG_BRIGHT,  # Colores al hacer clic
            relief="flat", cursor="hand2",  # Sin borde, cursor de mano
            font=(MONO, 11, "bold"),  # Fuente negrita
            padx=28, pady=18, justify="left",  # Espaciado y justificación
            highlightthickness=2, highlightbackground=ACCENT,  # Borde resaltado verde
        )
        b_enc.grid(row=0, column=0, padx=12, pady=6, sticky="nsew")
        # Cambiar color cuando el ratón entra (efecto hover)
        b_enc.bind("<Enter>", lambda e: b_enc.config(bg=BTN_HOV))
        # Cambiar color cuando el ratón sale
        b_enc.bind("<Leave>", lambda e: b_enc.config(bg=BTN_BG))

        # ─ SEPARADOR VERTICAL ────────────────────────────────────────────────────
        tk.Frame(btn_frame, bg=BORDER, width=1).grid(
            row=0, column=1, padx=4, sticky="ns")

        # ─ BOTÓN 2: DESENCRIPTAR ────────────────────────────────────────────────
        b_dec = tk.Button(
            btn_frame,
            # Texto con instrucciones paso a paso
            text="DESENCRIPTAR\n\n◆ Define dimensiones\n◆ Ingresa matriz clave\n◆ Recupera el mensaje",
            command=lambda: DecryptWindow(self),  # Abrir ventana de desencriptación
            bg=BTN_BG, fg=WARN,  # Colores naranja de advertencia
            activebackground=BTN_HOV, activeforeground=WARN,  # Colores al hacer clic
            relief="flat", cursor="hand2",  # Sin borde, cursor de mano
            font=(MONO, 11, "bold"),  # Fuente negrita
            padx=28, pady=18, justify="left",  # Espaciado y justificación
            highlightthickness=2, highlightbackground=WARN,  # Borde resaltado naranja
        )
        b_dec.grid(row=0, column=2, padx=12, pady=6, sticky="nsew")
        # Cambiar color cuando el ratón entra
        b_dec.bind("<Enter>", lambda e: b_dec.config(bg=BTN_HOV))
        # Cambiar color cuando el ratón sale
        b_dec.bind("<Leave>", lambda e: b_dec.config(bg=BTN_BG))

        # ═ SECCIÓN: PIE DE PÁGINA (CRÉDITOS) =========================================
        # Línea separadora horizontal
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=12, pady=(8, 0))
        # Texto de créditos y detalles de la aplicación
        mk_label(
            self,
            "  Luis Lopez · Mario Corado  ·  Álgebra Lineal  ·  UMES  ",
            size=8, color=FG_DIM,
        ).pack(pady=(4, 14))
    def _animate_sub(self, full_text, idx=0):
        """Efecto de escritura progresiva (typing effect) en el subtítulo."""
        # Si aún no hemos llegado al final del texto
        if idx <= len(full_text):
            # Mostrar los primeros idx caracteres + un cursor parpadeante (█)
            self._sub_var.set(full_text[:idx] + ("█" if idx < len(full_text) else ""))
            # Programar la siguiente actualización después de 35 milisegundos
            self.after(35, self._animate_sub, full_text, idx + 1)

# ══════════════════════════════ ENTRY POINT ════════════════════════════════════
# Punto de entrada del programa

if __name__ == "__main__":
    # Intentar importar numpy (librería para operaciones matriciales)
    try:
        import numpy as np  # noqa: F811 (importar aunque ya esté arriba)
    except ImportError:
        # Si numpy no está instalado, instalarlo automáticamente
        import sys, subprocess
        print("📦 Instalando numpy (necesario para cálculos matriciales)...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "numpy"])
        import numpy as np  # noqa: F811 (importar después de instalar)

    # Crear la aplicación (ventana principal)
    app = MatrixCipher()
    # Iniciar el evento de la interfaz gráfica (loop infinito hasta que se cierre)
    app.mainloop()
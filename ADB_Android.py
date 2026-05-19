import customtkinter as ctk
from tkinter import filedialog, simpledialog, messagebox
import subprocess
import threading
import json
import re
import os
import platform
from datetime import datetime

# Configuración de apariencia
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

BLOATWARE_PACKAGES = [
    "com.miui.analytics", "com.miui.msa.global", "com.xiaomi.joyose", 
    "com.miui.daemon", "com.miui.bugreport", "com.xiaomi.discover", 
    "com.xiaomi.mipicks", "com.miui.yellowpage", "com.tencent.soter.soterserver", 
    "com.facebook.services", "com.facebook.system", "com.facebook.appmanager", 
    "cn.wps.xiaomi.abroad.lite", "com.xiaomi.micloud.sdk", "com.miui.micloudsync", 
    "com.miui.cloudservice", "com.miui.cloudbackup", "com.xiaomi.simactivate.service",
    "com.dti.folderlauncher", "com.dti.zte", "com.wapi.wapic", "com.king.candycrushsoda", "com.king.candycrushsaga"
]

class AndroidHardeningSuite(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Android Hardening & Professional Audit Suite V3")
        self.geometry("1250x800")
        self.adb_path = None
        self.audit_data = {}

        # Layout Principal
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ----------------- SIDEBAR -----------------
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(10, weight=1)
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Audit Suite V3", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        # Botones de Acción Rápida
        ctk.CTkButton(self.sidebar_frame, text="Detectar Dispositivo", command=lambda: self.run_thread(self.detect_device)).grid(row=1, column=0, padx=20, pady=10)
        ctk.CTkButton(self.sidebar_frame, text="Auditoría Completa", fg_color="#27AE60", hover_color="#1E8449", command=lambda: self.run_thread(self.execute_full_audit)).grid(row=2, column=0, padx=20, pady=10)
        ctk.CTkButton(self.sidebar_frame, text="Neutralizar Bloatware", fg_color="#C0392B", hover_color="#922B21", command=lambda: self.run_thread(self.neutralize_bloatware)).grid(row=3, column=0, padx=20, pady=10)
        ctk.CTkButton(self.sidebar_frame, text="Exportar a JSON", command=self.export_report).grid(row=4, column=0, padx=20, pady=10)
        ctk.CTkButton(self.sidebar_frame, text="Limpiar Consola", fg_color="gray30", hover_color="gray20", command=self.clear_console).grid(row=5, column=0, padx=20, pady=10)

        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Estado: Inicializando...", text_color="yellow")
        self.status_label.grid(row=10, column=0, padx=20, pady=20, sticky="s")

        # ----------------- TABS CENTRALES -----------------
        self.tabview = ctk.CTkTabview(self, width=900)
        self.tabview.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        self.tab_console = self.tabview.add("Consola")
        self.tab_audit = self.tabview.add("Auditoría Avanzada")
        self.tab_hardening = self.tabview.add("Hardening OS")
        self.tab_apps = self.tabview.add("App Manager")
        self.tab_net = self.tabview.add("Control Red")
        self.tab_logs = self.tabview.add("Logs y Utils")

        # SETUP DE CADA PESTAÑA
        self.setup_console_tab()
        self.setup_audit_tab()
        self.setup_hardening_tab()
        self.setup_apps_tab()
        self.setup_net_tab()
        self.setup_logs_tab()

        self.run_thread(self.setup_adb)

    # ================== CONSTRUCCIÓN DE UI ==================
    def setup_console_tab(self):
        self.tab_console.grid_columnconfigure(0, weight=1)
        self.tab_console.grid_rowconfigure(0, weight=1)
        
        self.console_textbox = ctk.CTkTextbox(self.tab_console, font=ctk.CTkFont(family="Consolas", size=13), text_color="#00FF00", fg_color="#111111")
        self.console_textbox.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 0))
        self.console_textbox.configure(state="disabled")

        frm_cmd = ctk.CTkFrame(self.tab_console, fg_color="transparent")
        frm_cmd.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        frm_cmd.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(frm_cmd, text="adb shell", font=ctk.CTkFont(family="Consolas", weight="bold")).grid(row=0, column=0, padx=(0, 10))
        self.cmd_entry = ctk.CTkEntry(frm_cmd, font=ctk.CTkFont(family="Consolas"))
        self.cmd_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.cmd_entry.bind("<Return>", lambda event: self.run_custom_command())
        ctk.CTkButton(frm_cmd, text="Ejecutar", width=80, command=self.run_custom_command).grid(row=0, column=2)

    def setup_audit_tab(self):
        self.tab_audit.grid_columnconfigure((0, 1), weight=1)
        
        frm1 = ctk.CTkFrame(self.tab_audit)
        frm1.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(frm1, text="Análisis de Vulnerabilidades", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(frm1, text="Buscar Binarios SetUID (-4000)", command=lambda: self.run_thread(lambda: self.run_adb_log("shell find /system /vendor /data -perm -4000 -type f 2>/dev/null"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm1, text="Verificar Root / Magisk", command=lambda: self.run_thread(lambda: self.run_adb_log("shell which su || echo 'No su binary found'"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm1, text="Volcado DPM (Device Policy)", command=lambda: self.run_thread(lambda: self.run_adb_log("shell dumpsys device_policy"))).pack(pady=5, fill="x", padx=20)

        frm2 = ctk.CTkFrame(self.tab_audit)
        frm2.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(frm2, text="Análisis Dinámico", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(frm2, text="Listar Sockets de Red Activos (ss)", command=lambda: self.run_thread(lambda: self.run_adb_log("shell ss -tupan | grep ESTAB"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm2, text="Estadísticas de Memoria (RAM/Swap)", command=lambda: self.run_thread(lambda: self.run_adb_log("shell cat /proc/meminfo"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm2, text="Espacio en Disco (/data)", command=lambda: self.run_thread(lambda: self.run_adb_log("shell df -h /data"))).pack(pady=5, fill="x", padx=20)

    def setup_hardening_tab(self):
        self.tab_hardening.grid_columnconfigure((0, 1), weight=1)
        
        frm1 = ctk.CTkFrame(self.tab_hardening)
        frm1.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(frm1, text="Optimización y Entorno", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(frm1, text="Bypass Phantom Process Killer (Android 12+)", command=lambda: self.run_thread(self.disable_phantom_killer)).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm1, text="Compilación ART Nativa (Speed Profile)", command=lambda: self.run_thread(lambda: self.run_adb_log("shell cmd package bg-dexopt-job"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm1, text="Acelerar Animaciones WM (0.5x)", command=lambda: self.run_thread(self.optimize_system)).pack(pady=5, fill="x", padx=20)

        frm2 = ctk.CTkFrame(self.tab_hardening)
        frm2.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(frm2, text="Aislamiento", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(frm2, text="Purgar Telemetría Work Profile (User 10)", fg_color="#C0392B", hover_color="#922B21", command=lambda: self.run_thread(self.neutralize_work_profile)).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm2, text="Desactivar Orígenes Desconocidos", command=lambda: self.run_thread(lambda: self.run_adb_log("shell settings put secure install_non_market_apps 0"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm2, text="Activar Orígenes Desconocidos", command=lambda: self.run_thread(lambda: self.run_adb_log("shell settings put secure install_non_market_apps 1"))).pack(pady=5, fill="x", padx=20)

    def setup_apps_tab(self):
        self.tab_apps.grid_columnconfigure((0, 1), weight=1)
        
        frm1 = ctk.CTkFrame(self.tab_apps)
        frm1.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(frm1, text="Instalación y Desinstalación", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(frm1, text="Instalar APK (Global)", command=self.install_apk).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm1, text="Desinstalar App Manual", command=self.uninstall_app).pack(pady=5, fill="x", padx=20)

        frm2 = ctk.CTkFrame(self.tab_apps)
        frm2.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(frm2, text="Listados", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(frm2, text="Listar Apps de Terceros", command=lambda: self.run_thread(lambda: self.run_adb_log("shell pm list packages -3"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm2, text="Listar Usuarios (Contenedores)", command=lambda: self.run_thread(lambda: self.run_adb_log("shell pm list users"))).pack(pady=5, fill="x", padx=20)

    def setup_net_tab(self):
        self.tab_net.grid_columnconfigure(0, weight=1)
        frm = ctk.CTkFrame(self.tab_net)
        frm.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(frm, text="Control de Hardware de Red", font=ctk.CTkFont(weight="bold")).pack(pady=20)
        ctk.CTkButton(frm, text="Desactivar WiFi", command=lambda: self.run_thread(lambda: self.run_adb_log("shell svc wifi disable"))).pack(pady=5, fill="x", padx=100)
        ctk.CTkButton(frm, text="Activar WiFi", command=lambda: self.run_thread(lambda: self.run_adb_log("shell svc wifi enable"))).pack(pady=5, fill="x", padx=100)
        ctk.CTkButton(frm, text="Desactivar Bluetooth", command=lambda: self.run_thread(lambda: self.run_adb_log("shell service call bluetooth_manager 8"))).pack(pady=5, fill="x", padx=100)
        ctk.CTkButton(frm, text="Desactivar GPS", command=lambda: self.run_thread(lambda: self.run_adb_log("shell settings put secure location_mode 0"))).pack(pady=5, fill="x", padx=100)

    def setup_logs_tab(self):
        self.tab_logs.grid_columnconfigure((0, 1), weight=1)
        
        frm1 = ctk.CTkFrame(self.tab_logs)
        frm1.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(frm1, text="Logcat", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(frm1, text="Volcado Logcat (Completo)", command=lambda: self.run_thread(lambda: self.run_adb_log("logcat -d"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm1, text="Volcado Logcat (Security)", command=lambda: self.run_thread(lambda: self.run_adb_log("logcat -b security -d"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm1, text="Limpiar Buffer de Logs", command=lambda: self.run_thread(lambda: self.run_adb_log("logcat -c"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm1, text="Tomar Captura de Pantalla", command=lambda: self.run_thread(self.take_screenshot)).pack(pady=20, fill="x", padx=20)

        frm2 = ctk.CTkFrame(self.tab_logs)
        frm2.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(frm2, text="Energía", font=ctk.CTkFont(weight="bold")).pack(pady=10)
        ctk.CTkButton(frm2, text="Reiniciar (Normal)", command=lambda: self.run_thread(lambda: self.run_adb_log("reboot"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm2, text="Reiniciar (Bootloader)", fg_color="#D68910", hover_color="#B9770E", command=lambda: self.run_thread(lambda: self.run_adb_log("reboot bootloader"))).pack(pady=5, fill="x", padx=20)
        ctk.CTkButton(frm2, text="Reiniciar (Recovery)", fg_color="#D68910", hover_color="#B9770E", command=lambda: self.run_thread(lambda: self.run_adb_log("reboot recovery"))).pack(pady=5, fill="x", padx=20)

    # ================== LÓGICA ADB Y MOTOR ==================
    def log(self, message):
        self.console_textbox.configure(state="normal")
        self.console_textbox.insert("end", str(message) + "\n")
        self.console_textbox.see("end")
        self.console_textbox.configure(state="disabled")

    def clear_console(self):
        self.console_textbox.configure(state="normal")
        self.console_textbox.delete("0.0", "end")
        self.console_textbox.configure(state="disabled")

    def run_thread(self, target_func):
        threading.Thread(target=target_func, daemon=True).start()

    def run_adb(self, command, timeout=15):
        if not self.adb_path: return "Error ADB no inicializado"
        try:
            full_command = f'"{self.adb_path}" {command}'
            result = subprocess.run(full_command, shell=True, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0:
                return f"[!] Error ADB: {result.stderr.strip()}"
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "[TIMEOUT] El comando tardó demasiado."
        except Exception as e:
            return f"Error de ejecución: {str(e)}"

    def run_adb_log(self, command):
        self.log(f"\n> adb {command}")
        self.log(self.run_adb(command))

    def run_custom_command(self):
        cmd = self.cmd_entry.get().strip()
        if cmd:
            self.cmd_entry.delete(0, 'end')
            self.run_thread(lambda: self.run_adb_log(f"shell {cmd}"))

    def setup_adb(self):
        self.log("[*] Inicializando entorno ADB...")
        try:
            subprocess.run(["adb", "version"], capture_output=True, check=True)
            self.adb_path = "adb"
            self.log("[+] ADB detectado en PATH del sistema.")
        except:
            self.adb_path = os.path.join(os.getcwd(), "platform-tools", "adb.exe")
            self.log("[!] Usando ADB local fallback.")
        self.run_adb("start-server")
        self.status_label.configure(text="Estado: Listo", text_color="green")

    def detect_device(self):
        out = self.run_adb("devices")
        lines = out.strip().splitlines()
        found = False
        for line in lines:
            if "device" in line and "List" not in line:
                self.log(f"\n[+] Dispositivo detectado: {line.split()[0]}")
                self.status_label.configure(text="Estado: Dispositivo OK", text_color="green")
                found = True
        if not found:
            self.log("\n[-] Ningún dispositivo autorizado encontrado.")
            self.status_label.configure(text="Estado: Sin Dispositivo", text_color="red")

    # ================== RUTINAS PROFESIONALES ==================
    def execute_full_audit(self):
        self.log("\n" + "="*50)
        self.log(" INICIANDO AUDITORÍA PROFESIONAL DE SEGURIDAD")
        self.log("="*50)
        
        self.audit_data = {"timestamp": datetime.now().isoformat()}

        model = self.run_adb("shell getprop ro.product.model")
        serial = self.run_adb("shell getprop ro.serialno")
        os_ver = self.run_adb("shell getprop ro.build.version.release")
        self.log(f"\n[+] --- IDENTIFICACIÓN ---\n    Modelo: {model}\n    Android: {os_ver}\n    Serial: {serial}")

        selinux = self.run_adb("shell getenforce")
        crypto = self.run_adb("shell getprop ro.crypto.state")
        bl = "Bloqueado (Seguro)" if self.run_adb("shell getprop ro.boot.flash.locked") == "1" else "Desbloqueado (Vulnerable)"
        self.log(f"\n[+] --- SEGURIDAD ---\n    SELinux: {selinux}\n    Cifrado: {crypto}\n    Bootloader: {bl}")

        installed = self.run_adb("shell pm list packages")
        found_bloat = [p for p in BLOATWARE_PACKAGES if p in installed]
        self.log(f"\n[+] --- TELEMETRÍA ---\n    Paquetes detectados: {found_bloat}")

        batt = self.run_adb("shell dumpsys battery")
        lvl = re.search(r'level:\s+(\d+)', batt)
        if lvl: self.log(f"\n[+] --- HARDWARE ---\n    Batería: {lvl.group(1)}%")

        self.audit_data = {"model": model, "security": {"selinux": selinux, "bootloader": bl}, "telemetry": found_bloat}
        self.log("\n[*] Auditoría finalizada exitosamente.")
        self.tabview.set("Consola")

    def neutralize_bloatware(self):
        self.log("\n[*] Iniciando mitigación de Bloatware (User 0)...")
        for pkg in BLOATWARE_PACKAGES:
            res = self.run_adb(f"shell pm uninstall -k --user 0 {pkg}")
            if "Success" in res: self.log(f"    [+] {pkg} purgado.")
        self.log("[✓] Limpieza completada.")

    def neutralize_work_profile(self):
        self.log("\n[*] Purgando contenedores de terceros en User 10...")
        target_pkgs = ["com.miui.analytics", "com.facebook.system", "com.facebook.services", "com.facebook.appmanager", "com.tencent.soter.soterserver"]
        for pkg in target_pkgs:
            res = self.run_adb(f"shell pm uninstall -k --user 10 {pkg}")
            self.log(f"    -> {pkg}: {res}")
        self.log("[✓] Aislamiento del Work Profile completado.")

    def optimize_system(self):
        self.log("\n[*] Modificando políticas del Window Manager...")
        self.run_adb("shell settings put global window_animation_scale 0.5")
        self.run_adb("shell settings put global transition_animation_scale 0.5")
        self.run_adb("shell settings put global animator_duration_scale 0.5")
        self.log("[✓] Animaciones aceleradas.")

    def disable_phantom_killer(self):
        self.log("\n[*] Deshabilitando Phantom Process Killer...")
        res1 = self.run_adb("shell device_config put activity_manager max_phantom_processes 2147483647")
        res2 = self.run_adb("shell device_config put activity_manager settings_use_freezer false")
        self.log(f"    Config max_phantom: {res1}\n    Config use_freezer: {res2}")
        self.log("[✓] Limites de procesos en background removidos.")

    def take_screenshot(self):
        self.log("\n[*] Capturando pantalla...")
        filename = f"screencap_{datetime.now().strftime('%H%M%S')}.png"
        self.run_adb(f"shell screencap -p /sdcard/{filename}")
        res = self.run_adb(f"pull /sdcard/{filename} .")
        self.run_adb(f"shell rm /sdcard/{filename}")
        self.log(f"[+] {res}")

    def install_apk(self):
        path = filedialog.askopenfilename(filetypes=[("APK", "*.apk")])
        if path: self.run_thread(lambda: self.run_adb_log(f'install "{path}"'))

    def uninstall_app(self):
        pkg = simpledialog.askstring("Desinstalar App", "Nombre del paquete (ej: com.android.chrome):")
        if pkg: self.run_thread(lambda: self.run_adb_log(f"shell pm uninstall --user 0 {pkg}"))

    def export_report(self):
        filename = f"AuditReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, "w") as f:
                json.dump(self.audit_data, f, indent=4)
            self.log(f"\n[+] Evidencia exportada a {filename}")
        except Exception as e:
            self.log(f"\n[-] Error al exportar: {e}")

if __name__ == "__main__":
    app = AndroidHardeningSuite()
    app.mainloop()
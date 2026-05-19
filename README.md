# 🛡️ Android Hardening & Professional Audit Suite V3

Herramienta avanzada desarrollada en Python para la auditoría, bastionado (hardening) y gestión forense de dispositivos Android a través de ADB. Diseñada específicamente para pentesters y auditores de seguridad corporativa que requieren aislar entornos de trabajo (Work Profiles), neutralizar telemetría nativa en capas de personalización (como MIUI) y extraer métricas de seguridad en despliegues autorizados.

## 🚀 Características Principales

Esta suite opera mediante un motor multihilo para evitar el bloqueo de la interfaz y cuenta con auto-aprovisionamiento del binario `adb` en caso de no detectarlo en el sistema host.

### 🕵️ Auditoría de Seguridad Avanzada

* **Postura Criptográfica:** Validación del estado del cifrado (/data), políticas de SELinux y estado de bloqueo del Bootloader.
* **Análisis de Vulnerabilidades:** Búsqueda automática de binarios `SetUID` (-4000), detección de binarios `su` (Root/Magisk) y volcado de políticas DPM (*Device Policy Manager*).
* **Auditoría de Red:** Extracción de sockets TCP establecidos en tiempo real mediante `ss`.

### 🗑️ Aislamiento y Neutralización (Debloat)

* **Hardening del SO Base (User 0):** Erradicación de telemetría de fabricantes (MIUI Analytics, MSA), frameworks de terceros integrados (Facebook Services, Tencent Soter) y bloatware.
* **Aislamiento de Work Profile (User 10):** Destrucción selectiva de paquetes clonados por el sistema dentro del contenedor corporativo para evitar fugas de datos (Data Leakage).

### ⚡ Optimización del Sistema (SoC Tuning)

* **Bypass de Restricciones (Android 12+):** Neutralización del *Phantom Process Killer* para evitar que el SO mate aplicaciones críticas en background (Teams, VPNs).
* **Compilación ART Nativa:** Ejecución de `bg-dexopt-job` para forzar la compilación *Ahead-Of-Time* (AOT) a código máquina y eliminar la latencia JIT.
* **Aceleración de UI:** Ajuste de interpolación en el Window Manager.

### 📜 Extracción Forense y Evidencia

* Volcados segmentados de `logcat` (General y Security buffers).
* Capturas de pantalla directas al host local.
* Exportación automática del estado del dispositivo a un reporte estructurado en formato **JSON**.

---

## 🛠️ Requisitos e Instalación

### Prerrequisitos

* Python 3.8 o superior.
* Dispositivo Android con **Depuración USB** (USB Debugging) habilitada y autorizada. Para dispositivos Xiaomi/MIUI, es mandatorio habilitar **Depuración USB (Ajustes de Seguridad)**.

### Instalación

1. Clona este repositorio:
   ```bash
   git clone [[https://github.com/tu_usuario/android-hardening-suite.git](https://github.com/tu_usuario/android-hardening-suite.git)
   cd android-hardening-suite](https://github.com/RogerF5-Security/ADB_Hardening_Android.git)

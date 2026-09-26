# WIfiAudit

Suite de auditoría WiFi para Windows. Escanea tu red, detecta vecinos, analiza canales, mantiene histórico de señal, captura handshakes y sniffa clientes. Todo local, sin telemetría.

## Qué hace

| Opción | Descripción | Salida |
|---|---|---|
| 1 | Mi WiFi — conexión actual, perfiles guardados, dispositivos LAN | `Results/MiWIfi/` |
| 2 | Wifis cercanas — barrido completo de BSS | `Results/Near Wifis/` |
| 3 | Ambas combinadas | `Results/MiWIfi and Near Wifis/` |
| 4 | Análisis de canales — congestión y recomendación | `Results/Channels/` |
| 5 | Histórico RSSI — acumulativo con gráfico | `Results/History/` |
| 6 | Handshake + hashcat `[adaptador monitor]` | `Results/Handshakes/` |
| 7 | Clientes por BSSID `[adaptador monitor]` | `Results/Clients/` |

Formatos: txt (defecto), json, html — combinables con `--format`.

## Requisitos

**Build:**
- Visual Studio 2022 con workload **Desarrollo de escritorio con C++**
- Windows 11 SDK (viene con el workload)

**Runtime:**
- Windows 10/11 x64
- Servicio WLAN AutoConfig activo
- Permisos de administrador

**Opciones 6 y 7 (binarios externos en PATH):**

| Binario | Origen |
|---|---|
| `dumpcap.exe` | Wireshark / Npcap |
| `tshark.exe` | Wireshark |
| `hcxpcapngtool.exe` | github.com/ZerBea/hcxtools |
| `hashcat.exe` | hashcat.net |
| `WlanHelper.exe` | Npcap SDK / Wireshark extcap |

Verificar:
```powershell
foreach ($e in 'dumpcap','tshark','hashcat','hcxpcapngtool','WlanHelper') {
    $p = Get-Command $e -ErrorAction SilentlyContinue
    if ($p) { Write-Host "[ok] $e" } else { Write-Host "[!] missing: $e" }
}
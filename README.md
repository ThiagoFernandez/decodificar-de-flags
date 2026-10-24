# decodificar-de-flags

Decodificador de los **flags de autoconfiguración IPv6** (A / M / O) a partir de los **Router
Advertisements (RA)** que captura de la red con **scapy**. Dado un RA, dice en qué **modo** está la
red —**SLAAC puro**, **stateless** o **stateful**— y de dónde saca el host la **dirección** y el **DNS**.

> Práctica de código diaria. Junta dos cosas que vengo trabajando: los flags de DHCPv6 / SLAAC
> (CCNA 2, Módulo 8) y la captura de paquetes con scapy (roadmap de ciberseguridad).

## Los flags y lo que significan

El modo lo deciden tres flags del RA:

- **M** (*Managed*) — en el header del RA. Si **1**, el host pide la **dirección** por DHCPv6 (stateful).
- **O** (*Other*) — en el header del RA. Si **1**, el host pide **info adicional** (DNS, dominio) por DHCPv6.
- **A** (*Autonomous*) — **en la opción Prefix Information**, no en el header. Si **1**, el host arma
  la dirección por **SLAAC** (prefijo del RA + EUI-64).

| A | M | O | Modo | Dirección | DNS / info |
|:-:|:-:|:-:|---|---|---|
| 1 | 0 | 0 | **SLAAC puro** | SLAAC (prefijo + EUI-64) | — (no hay DHCPv6) |
| 1 | 0 | 1 | **SLAAC + stateless** | SLAAC | servidor DHCPv6 |
| x | 1 | x | **stateful** | servidor DHCPv6 (pool) | servidor DHCPv6 |
| 0 | 0 | 0 | solo link-local | — | — |

> ⚠️ **Detalle clave:** el flag **A no está en el header del RA**, sino en la **opción Prefix
> Information**. Por eso el script lo saca de `ICMPv6NDOptPrefixInfo`, no de `ICMPv6ND_RA`.

## Uso

Necesita **scapy** y permisos de captura (admin / sudo; en Windows, **Npcap**).

```bash
sudo python main.py -i eth0 -d 10
```

- `-i` / `--iface`: interfaz a escuchar (default: la que elija scapy).
- `-d` / `--duration`: segundos de captura; `0` = infinito.

## Cómo probarlo

Como depende de que haya un RA real en la red (y solo verías el modo que anuncia tu router), la
forma **determinística** de testear los cuatro casos es **craftear** RAs de prueba con scapy —que
además de sniffear, **crea** paquetes— y pasárselos directo a `procesar_paquete(...)`, uno por modo:

```python
ra = ICMPv6ND_RA(M=1, O=0) / ICMPv6NDOptPrefixInfo(A=0, prefix="2001:db8::", prefixlen=64)
procesar_paquete(ra)   # -> DHCPv6 stateful
```

Repetir variando A / M / O para cubrir SLAAC puro, stateless, stateful y solo link-local.

---

*ICMPv6 · Router Advertisement · scapy · CCNA 2 Módulo 8.*

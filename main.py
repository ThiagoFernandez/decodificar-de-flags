from scapy.all import (
    Scapy_Exception,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    sniff,
)
import argparse

def crear_args():
    p = argparse.ArgumentParser(description="Decodificador de flags ICMPv6 RA")
    p.add_argument("-i", "--iface", default=None, help="interfaz de red")
    p.add_argument(
        "-d", "--duration", type=int, default=10,
        help="duración en segundos; 0 = infinito"
    )
    return p.parse_args()

def procesar_paquete(pkt):
    if not pkt.haslayer(ICMPv6ND_RA):
        return

    ra = pkt[ICMPv6ND_RA]
    m = int(ra.M)
    o = int(ra.O)

    # El flag A esta en la opt de info de prefijo, no en el RA.
    prefijos = pkt.getlayer(ICMPv6NDOptPrefixInfo, nb=1)
    a = int(prefijos.A) if prefijos else None

    if m == 1:
        tipo = "DHCPv6 stateful"
        proveedor_ip = "servidor dhcp(de la pool)"
        proveedor_adicional = "servidor dhcp"
    elif m == 0 and o == 1:
        tipo = "SLAAC + DHCPv6 stateless"
        proveedor_ip = "prefijo de red(eui-64)"
        proveedor_adicional = "servidor dhcp"
    elif m == 0 and a == 1:
        tipo = "SLAAC"
        proveedor_ip = "prefijo de red(eui-64)"
        proveedor_adicional = "no tiene"
    elif m == 0 and o == 0 and a == 0:
        tipo = "Solo link-local / sin configuración anunciada"
        proveedor_ip = "no tiene"
        proveedor_adicional = "no tiene"
    else:
        tipo = "Combinación no clasificada"
        proveedor_ip = "n/a"
        proveedor_adicional = "n/a"

    print(f"Tipo de configuración anunciado: {tipo}")
    print(f"M={m}, O={o}, A={a}")
    print(f"De donde saca el host la direccion: {proveedor_ip}")
    print(f"De donde saca el host la info adicional: {proveedor_adicional}")

def sniff_network(args):
    try:
        sniff(
            filter="icmp6",
            prn=procesar_paquete,
            store=False,
            iface=args.iface,
            timeout=args.duration if args.duration > 0 else None,
        )
    except KeyboardInterrupt:
        print("Cerrando programa...")
    except PermissionError:
        print("Error: permisos insuficientes. Ejecuta el script con permisos de captura.")
    except Scapy_Exception as e:
        print(f"Error de Scapy: {e}")
    except OSError as e:
        print(f"Error de red: {e}")

def main():
    args = crear_args()
    sniff_network(args)

if __name__ == "__main__":
    main()

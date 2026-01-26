#!/usr/bin/env python3
import sys, random, argparse, ipaddress
from collections import defaultdict

privRanges = [
    #('10.0.0.0', '10.255.255.255'),
    #('172.16.0.0', '172.31.255.255'),
    #('192.168.0.0', '192.168.255.255'),
    #('127.0.0.0', '127.255.255.255'),
    #('169.254.0.0', '169.254.255.255'),
    #('224.0.0.0', '239.255.255.255'),  # Multicast
    #('240.0.0.0', '255.255.255.255'),  # Reservado
]

Mranges = [
    # AWS
    ('3.0.0.0', '3.255.255.255'),
    ('13.0.0.0', '13.255.255.255'),
    ('18.0.0.0', '18.255.255.255'),
    ('52.0.0.0', '52.255.255.255'),
    ('54.0.0.0', '54.255.255.255'),
    
    # Go Cloud
    ('34.0.0.0', '34.255.255.255'),
    ('35.0.0.0', '35.255.255.255'),
    
    ('20.0.0.0', '20.255.255.255'),
    ('40.0.0.0', '40.127.255.255'),
    
    # Cloudflare
    ('104.16.0.0', '104.31.255.255'),
    
    # DigitalOcean
    ('67.205.0.0', '67.205.255.255'),
    ('159.65.0.0', '159.65.255.255'),
    
    # Akamai
    ('23.0.0.0', '23.255.255.255'),
    
    # OVH
    ('51.0.0.0', '51.255.255.255'),
]

Cranges = {
    'US': [
        ('8.0.0.0', '8.255.255.255'),
        ('12.0.0.0', '12.255.255.255'),
        ('44.0.0.0', '44.255.255.255'),
    ],
    'CN': [
        ('1.0.0.0', '1.255.255.255'),
        ('14.0.0.0', '14.255.255.255'),
        ('27.0.0.0', '27.255.255.255'),
    ],
    'EU': [
        ('2.0.0.0', '2.255.255.255'),
        ('31.0.0.0', '31.255.255.255'),
        ('46.0.0.0', '46.255.255.255'),
    ],
}

def ipToInt(ip):
    parts = ip.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def intToIp(num):
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"

def isPrivateIp(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_loopback
    except:
        return True

def isValidIp(ip):
    try:
        parts = [int(x) for x in ip.split('.')]
        
        if parts[0] == 0 or parts[0] >= 224:
            return False
        
        if parts[0] == 127:
            return False
        
        if parts[0] == 169 and parts[1] == 254:  # Link-local
            return False
        
        if isPrivateIp(ip):
            return False
        
        return True
    except:
        return False


class iGen:
    def __init__(self):
        self.generated = set()
    
    def genFromPrefix(self, prefix, count):
        parts = prefix.split('.')
        num_parts = len(parts)
        
        if num_parts > 4:
            return []
        
        try:
            for part in parts:
                val = int(part)
                if val < 0 or val > 255:
                    return []
        except:
            return []
        
        ips = []
        attempts = 0
        max_attempts = count * 100
        
        while len(ips) < count and attempts < max_attempts:
            attempts += 1
            
            ip_parts = parts.copy()
            
            for i in range(num_parts, 4):
                if i == 3:
                    octeto = random.randint(1, 254)
                else:
                    if random.random() < 0.7:
                        octeto = random.choice([
                            random.randint(1, 63),
                            random.randint(64, 127),
                            random.randint(128, 191),
                            random.randint(192, 254)
                        ])
                    else:
                        octeto = random.randint(0, 255)
                
                ip_parts.append(str(octeto))
            
            ip = '.'.join(ip_parts)
            
            if ip not in self.generated and isValidIp(ip):
                self.generated.add(ip)
                ips.append(ip)
        
        return ips
    
    def genRs(self, count):
        ips = []
        attempts = 0
        max_attempts = count * 100
        
        while len(ips) < count and attempts < max_attempts:
            attempts += 1
            
            method = random.choices(
                ['major_provider', 'country', 'general'],
                weights=[40, 30, 30]
            )[0]
            
            if method == 'major_provider':
                range_start, range_end = random.choice(Mranges)
                ip = self.genInRange(range_start, range_end)
            
            elif method == 'country':
                country = random.choice(list(Cranges.keys()))
                range_start, range_end = random.choice(Cranges[country])
                ip = self.genInRange(range_start, range_end)
            
            else:
                ip = self.genGeneral()
            
            if ip and ip not in self.generated and isValidIp(ip):
                self.generated.add(ip)
                ips.append(ip)
        
        return ips
    
    def genInRange(self, start, end):
        start_int = ipToInt(start)
        end_int = ipToInt(end)
        
        random_int = random.randint(start_int, end_int)
        return intToIp(random_int)
    
    def genGeneral(self):

        first = random.choice([
            random.randint(1, 9),
            random.randint(11, 126),
            random.randint(128, 168),
            random.randint(170, 171),
            random.randint(173, 191),
            random.randint(193, 223)
        ])
        
        second = random.randint(0, 255)
        third = random.randint(0, 255)
        fourth = random.randint(1, 254)
        
        return f"{first}.{second}.{third}.{fourth}"
    
    def genSeq(self, prefix, count):
        parts = prefix.split('.')
        num_parts = len(parts)
        
        if num_parts > 4:
            return []
        
        ips = []
        base_parts = [int(p) for p in parts]
        
        while len(base_parts) < 4:
            base_parts.append(0)
        
        current = ipToInt('.'.join(map(str, base_parts)))
        
        while len(ips) < count:
            ip = intToIp(current)
            
            if isValidIp(ip):
                ips.append(ip)
            
            current += 1
            
            if current > 0xFFFFFFFF:
                break
        
        return ips
    
    def genSub(self, prefix, count):
        parts = prefix.split('.')
        num_parts = len(parts)
        
        if num_parts < 2:
            return []
        
        ips = []
        attempts = 0
        max_attempts = count * 50
        
        if num_parts == 2:
            base1, base2 = int(parts[0]), int(parts[1])
            
            while len(ips) < count and attempts < max_attempts:
                attempts += 1
                third = random.randint(0, 255)
                fourth = random.randint(1, 254)
                
                ip = f"{base1}.{base2}.{third}.{fourth}"
                
                if ip not in self.generated and isValidIp(ip):
                    self.generated.add(ip)
                    ips.append(ip)
        
        elif num_parts == 3:
            base1, base2, base3 = int(parts[0]), int(parts[1]), int(parts[2])
            
            for fourth in range(1, min(255, count + 1)):
                ip = f"{base1}.{base2}.{base3}.{fourth}"
                
                if isValidIp(ip):
                    ips.append(ip)
                
                if len(ips) >= count:
                    break
        
        return ips

def main():
    parser = argparse.ArgumentParser(
        description='iGen',
        add_help=False
    )
    
    parser.add_argument('-t', '--type', type=str,
                       help='Pref de IP (ej: 198.189 o 10.0.1)')
    parser.add_argument('-c', '--count', type=int, default=10,
                       help='Cant de IPs a generar (max 10000)')
    parser.add_argument('-m', '--mode', type=str, default='random',
                       choices=['random', 'sequential', 'subnet'],
                       help='Modo gen')
    parser.add_argument('-o', '--output', type=str,
                       help='Guardar')
    parser.add_argument('-h', '--help', action='store_true',
                       help='Mostrar this')
    
    args = parser.parse_args()
    
    if args.help or len(sys.argv) == 1:
        print("\n*[genip!]*")
        print("\n*TypeUse:*")
        print("  .genip -c 10                    Generar 10 IPs Al azar!")
        print("  .genip -t 198.189 -c 20         Generar 20 desde 198.189.x.x")
        print("  .genip -t 10.0 -c 100           Generar 100 desde 10.0.x.x")
        print("  .genip -t 8.8.8 -c 50           Generar 50 desde 8.8.8.x")
        print("  .genip -c 1000 -o ips.txt       Guardar file")
        print("  .genip -t 192.168 -m sequential Generar secuenciales!")
        print("  .genip -t 10.0 -m subnet        Generar por subredes!")
        print("\n*Ops:*")
        print("  -t, --type       Prefijo to ip")
        print("  -c, --count      Counter `1-10000`")
        print("  -m, --mode       Mode: `random`, `sequential`, `subnet`")
        print("  -o, --output     Archivo de salida")
        print("  -h, --help       this !!")
        print("\n*Modes*:")
        print("  random      IPs aleatorias!")
        print("  sequential  IPs consecutivas desde prefijo")
        print("  subnet      IPs dentro de subredes")
        print()
        return
    
    if args.count < 1 or args.count > 10000:
        print("[errCounter] cantidad 1 y 10000!")
        sys.exit(1)
    
    generator = iGen()
    
    #print(f"\n*[Gens `{args.count}` IPs]*")
    
    if args.type:
        print(f"*Pref*: `{args.type}`")
        print(f"*Mode*: `{args.mode}`")
    #else:
        #print(f"*Mode*: `Randomed!`")
    
    print()
    
    if args.type:
        if args.mode == 'sequential':
            ips = generator.genSeq(args.type, args.count)
        elif args.mode == 'subnet':
            ips = generator.genSub(args.type, args.count)
        else:  # random
            ips = generator.genFromPrefix(args.type, args.count)
    else:
        ips = generator.genRs(args.count)
    
    if not ips:
        print("*[err] No pude generar IPs... shit!*")
        sys.exit(1)
    
    first_octets = defaultdict(int)
    for ip in ips:
        first = ip.split('.')[0]
        first_octets[first] += 1

    for octeto in sorted(first_octets.keys(), key=lambda x: first_octets[x], reverse=True)[:5]:
        count = first_octets[octeto]
        percentage = (count / len(ips)) * 100

    #print(f"\n*[Gens!]*\n")
    
    for i, ip in enumerate(ips, 1):
        print(ip)
        
        if i % 50 == 0 and i < len(ips):
            print(f"\n*-x- `{i}/{len(ips)}` -x-*\n")
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                for ip in ips:
                    f.write(ip + '\n')
            print(f"\n[DONE!] IPs fileadas en: {args.output}")
        except Exception as e:
            print(f"\n[Err]: {e}")
    
    print()

if __name__ == "__main__":
    main()

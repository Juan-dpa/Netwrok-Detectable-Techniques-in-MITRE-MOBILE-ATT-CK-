import requests
from bs4 import BeautifulSoup
from utils_excel import Write_Dic_to_Excel, Write_List_to_Excel
import time
import openpyxl
            
def get_mitre_old_version(tactics, techniques, subtechniques, tactic_ids, technique_ids, subtechnique_ids, version_pedida, fecha):
    
    # Inicialización de las tácticas
    for tactic_id in tactic_ids:
        tactics[tactic_id, "Internet Scan"] = 'NO'
        tactics[tactic_id, "Network Share"] = 'NO'
        tactics[tactic_id, "Network Traffic"] = 'NO'
        tactics[tactic_id, "Network Detection"] = 'NO'
        tactics[tactic_id, "Only Network Detection"] = 'YES'
    # Inicialización de las técnicas
    for technique_id in technique_ids:
        techniques[technique_id, "Internet Scan"] = 'NO'
        techniques[technique_id, "Network Share"] = 'NO'
        techniques[technique_id, "Network Traffic"] = 'NO'
        techniques[technique_id, "Network Detection"] = 'NO'
        techniques[technique_id, "Only Network Detection"] = 'YES'

    # Se comprueba si cada subtécnica tiene como fuente el tráfico de red
    for subtechnique_id in subtechnique_ids:
        subtechnique_name = subtechniques[subtechnique_id, "Subtechnique Name"]
        technique_id = subtechniques[subtechnique_id, "Technique ID"]
        subtechnique_id_part = subtechnique_id.split('.')[1]
        # Se hace la petición a la URL de la subtécnica
        url = f"https://attack.mitre.org/versions/{version_pedida[1]}/techniques/{technique_id}/{subtechnique_id_part}/"
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Se comprueba si la subtécnica tiene como fuente el tráfico de red, y solo el tráfico de red
            internet_scan = 'NO'
            network_share = 'NO'
            network_traffic = 'NO'
            ataque_red = 'NO'
            solo_ataque_red = 'YES'
            all_datasources_elements = soup.find_all('a', href=lambda href: href and '/datasources/' in href)
            other_datasources = [element for element in all_datasources_elements if ('/datasources/DS0029' not in element['href'] and '/datasources/DS0033' not in element['href'] and '/datasources/DS0035' not in element['href'])]
            if any('/datasources/DS0035' in  el for el in [element['href'] for element in all_datasources_elements]):
                internet_scan = 'YES'
                techniques[technique_id, "Internet Scan"] = 'YES'
            if any('/datasources/DS0033' in  el for el in [element['href'] for element in all_datasources_elements]):
                network_share = 'YES'
                techniques[technique_id, "Network Share"] = 'YES'
            if any('/datasources/DS0029' in  el for el in [element['href'] for element in all_datasources_elements]):
                network_traffic = 'YES'
                techniques[technique_id, "Network Traffic"] = 'YES'
            if internet_scan == 'YES' or network_share == 'YES' or network_traffic == 'YES':
                ataque_red = 'YES'
                techniques[technique_id, "Network Detection"] = 'YES'
            if other_datasources:
                solo_ataque_red = 'NO'
                techniques[technique_id, "Only Network Detection"] = 'NO'

            # Se agrega al diccionario de subtécnicas
            subtechniques[subtechnique_id, "Internet Scan"] = internet_scan
            subtechniques[subtechnique_id, "Network Share"] = network_share
            subtechniques[subtechnique_id, "Network Traffic"] = network_traffic
            subtechniques[subtechnique_id, "Network Detection"] = ataque_red
            subtechniques[subtechnique_id, "Only Network Detection"] = solo_ataque_red
            print(f"Subtechnique ID: {subtechnique_id}, Subtechnique Name: {subtechnique_name}, Technique ID: {technique_id}")

            # Se espera 3 segundos antes de hacer la siguiente petición y evitar ser detectados como un ataque
            time.sleep(3)

        else:
            print(url)
            raise Exception("Error al realizar la solicitud:", response.status_code)

    # Se comprueba si cada técnica tiene como fuente el tráfico de red
    for technique_id in technique_ids:
        technique_name = techniques[technique_id, "Technique Name"]
        # Se hace la petición a la URL de la técnica
        url = f"https://attack.mitre.org/versions/{version_pedida[1]}/techniques/{technique_id}/"
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Inicialización de variables
            internet_scan = 'NO'
            network_share = 'NO'
            network_traffic = 'NO'
            ataque_red = 'NO'
            solo_ataque_red = 'YES'

            # Se comprueba si la técnica tiene como fuente el tráfico de red, y solo el tráfico de red
            all_datasources_elements = soup.find_all('a', href=lambda href: href and '/datasources/' in href)
            other_datasources = [element for element in all_datasources_elements if ('/datasources/DS0029' not in element['href'] and '/datasources/DS0033' not in element['href'] and '/datasources/DS0035' not in element['href'])]
            if any('/datasources/DS0035' in el for el in [element['href'] for element in all_datasources_elements]):
                internet_scan = 'YES'
                techniques[technique_id, "Internet Scan"] = 'YES'
            if any('/datasources/DS0033' in el for el in [element['href'] for element in all_datasources_elements]):
                network_share = 'YES'
                techniques[technique_id, "Network Share"] = 'YES'
            if any('/datasources/DS0029' in el for el in [element['href'] for element in all_datasources_elements]):
                network_traffic = 'YES'
                techniques[technique_id, "Network Traffic"] = 'YES'
            if internet_scan == 'YES' or network_share == 'YES' or network_traffic == 'YES':
                ataque_red = 'YES'
                techniques[technique_id, "Network Detection"] = 'YES'
            if other_datasources:
                solo_ataque_red = 'NO'
                techniques[technique_id, "Only Network Detection"] = 'NO'
            
            # Se extraen los enlaces de las tácticas asociadas a la técnica
            div_elements = soup.find_all('div', class_='col-md-11 pl-0')
            combined_div = BeautifulSoup("", 'html.parser')
            for div_element in div_elements:
                combined_div.append(div_element)
            tactic_links = combined_div.find_all('a', href=lambda href: href and '/tactics/' in href)

            # Se crea una lista con los IDs y los nombres de las tácticas
            tactics_list = []
            for link in tactic_links:
                tactic_id = link['href'].split('/')[-1]
                if techniques[technique_id, "Internet Scan"] == 'YES':
                    tactics[tactic_id, "Internet Scan"] = 'YES'
                if techniques[technique_id, "Network Share"] == 'YES':
                    tactics[tactic_id, "Network Share"] = 'YES'
                if techniques[technique_id, "Network Traffic"] == 'YES':
                    tactics[tactic_id, "Network Traffic"] = 'YES'
                if techniques[technique_id, "Network Detection"] == 'YES':
                    tactics[tactic_id, "Network Detection"] = 'YES'
                if techniques[technique_id, "Only Network Detection"] == 'NO':
                    tactics[tactic_id, "Only Network Detection"] = 'NO'
                tactic_name = link.text.strip()
                tactics_list.append((tactic_id, tactic_name))

            # Se obtienen los nombres y los IDs de las técnicas, para concatenarlos en una sola cadena
            tactic_ids2 = [tactic[0] for tactic in tactics_list]
            tactic_names = [tactic[1] for tactic in tactics_list]
            tactic_ids2 = " - ".join(tactic_ids2)
            tactic_names = " - ".join(tactic_names)

            # Se agrega al diccionario de técnicas
            techniques[technique_id, "Tactic IDs"] = tactic_ids2
            techniques[technique_id, "Tactic Names"] = tactic_names
            print(f"Technique ID: {technique_id}, Technique Name: {technique_name}, Tactic IDs: {tactic_ids2}, Tactic Names: {tactic_names}")

            # Se espera 3 segundos antes de hacer la siguiente petición y evitar ser detectados como un ataque
            time.sleep(3)

        else:
            raise Exception("Error al realizar la solicitud:", response.status_code)

    # Se calcula el número de técnicas de cada táctica
    for tactic_id in tactic_ids:
        tactic_name = tactics[tactic_id, "Tactic Name"]
        num_techniques = 0
        for technique_id in technique_ids:
            tactic_ids3 = techniques[technique_id, "Tactic IDs"]
            if tactic_id in tactic_ids3:
                num_techniques += 1
        tactics[tactic_id, "Number of Techniques"] = num_techniques
        #print(f"Tactic ID: {tactic_id}, Tactic Name: {tactic_name}, Number of Techniques: {num_techniques}")

    # Se crea un diccionario resumen
    summary = {}
    summary["Tactics", "Number"] = len(tactic_ids)
    num_is1 = 0
    num_ns1 = 0
    num_nt1 = 0
    num_nd1 = 0
    num_ond1 = 0
    for i in tactic_ids:
        if tactics[i, "Internet Scan"] == 'YES':
            num_is1 += 1
        if tactics[i, "Network Share"] == 'YES':
            num_ns1 += 1
        if tactics[i, "Network Traffic"] == 'YES':
            num_nt1 += 1
        if tactics[i, "Network Detection"] == 'YES':
            num_nd1 += 1
        if tactics[i, "Only Network Detection"] == 'YES':
            num_ond1 += 1
    summary["Tactics", "Internet Scan Detectable Items"] = num_is1
    summary["Tactics", "Network Share Detectable Items"] = num_ns1
    summary["Tactics", "Network Traffic Detectable Items"] = num_nt1
    summary["Tactics", "Network Detectable Items"] = num_nd1
    summary["Tactics", "Network Only Detectable Items"] = num_ond1
    summary["Techniques", "Number"] = len(technique_ids)

    num_is2 = 0
    num_ns2 = 0
    num_nt2 = 0
    num_nd2 = 0
    num_ond2 = 0
    for i in technique_ids:
        if techniques[i, "Internet Scan"] == 'YES':
            num_is2 += 1
        if techniques[i, "Network Share"] == 'YES':
            num_ns2 += 1
        if techniques[i, "Network Traffic"] == 'YES':
            num_nt2 += 1
        if techniques[i, "Network Detection"] == 'YES':
            num_nd2 += 1
        if techniques[i, "Only Network Detection"] == 'YES':
            num_ond2 += 1
    summary["Techniques", "Internet Scan Detectable Items"] = num_is2
    summary["Techniques", "Network Share Detectable Items"] = num_ns2
    summary["Techniques", "Network Traffic Detectable Items"] = num_nt2
    summary["Techniques", "Network Detectable Items"] = num_nd2
    summary["Techniques", "Network Only Detectable Items"] = num_ond2
    summary["Subtechniques", "Number"] = len(subtechnique_ids)

    num_is3 = 0
    num_ns3 = 0
    num_nt3 = 0
    num_nd3 = 0
    num_ond3 = 0
    for i in subtechnique_ids:
        if subtechniques[i, "Internet Scan"] == 'YES':
            num_is3 += 1
        if subtechniques[i, "Network Share"] == 'YES':
            num_ns3 += 1
        if subtechniques[i, "Network Traffic"] == 'YES':
            num_nt3 += 1
        if subtechniques[i, "Network Detection"] == 'YES':
            num_nd3 += 1
        if subtechniques[i, "Only Network Detection"] == 'YES':
            num_ond3 += 1
    summary["Subtechniques", "Internet Scan Detectable Items"] = num_is3
    summary["Subtechniques", "Network Share Detectable Items"] = num_ns3
    summary["Subtechniques", "Network Traffic Detectable Items"] = num_nt3
    summary["Subtechniques", "Network Detectable Items"] = num_nd3
    summary["Subtechniques", "Network Only Detectable Items"] = num_ond3

    # Se almacenan los diccionarios en un archivo excel
    try:
        excel_name = 'TechniquesTacticsMitre/TechniquesTactics.xlsx'
        # Se abre el archivo excel
        libro_excel = openpyxl.load_workbook(excel_name)
        sheet1 = libro_excel['Summary']
        columnas1 = ['Number', 'Internet Scan Detectable Items', 'Network Share Detectable Items', 'Network Traffic Detectable Items', 'Network Detectable Items', 'Network Only Detectable Items']
        sheet2 = libro_excel['Tactics']
        columnas2 = ['Tactic Name', 'Number of Techniques', 'Internet Scan', 'Network Share', 'Network Traffic', 'Network Detection', 'Only Network Detection']
        sheet3 = libro_excel['Techniques']
        columnas3 = ['Technique Name', 'Tactic IDs', 'Tactic Names', 'Number of Subtechniques', 'Internet Scan', 'Network Share', 'Network Traffic', 'Network Detection', 'Only Network Detection']
        sheet4 = libro_excel['Subtechniques']
        columnas4 = ['Subtechnique Name', 'Technique ID', 'Technique Name', 'Internet Scan', 'Network Share', 'Network Traffic', 'Network Detection', 'Only Network Detection']
        # Se escriben los diccionarios en el archivo excel
        Write_Dic_to_Excel(libro_excel, excel_name, sheet1, summary, 'B2', 'H5', ['Tactics', 'Techniques', 'Subtechniques'], columnas1)
        Write_List_to_Excel(libro_excel, excel_name, sheet1, fecha, 'B8', 'C8')
        Write_List_to_Excel(libro_excel, excel_name, sheet1, version_pedida, 'B9', 'C9')
        Write_Dic_to_Excel(libro_excel, excel_name, sheet2, tactics, 'B2', f'I{len(tactic_ids)+2}', tactic_ids, columnas2)
        Write_Dic_to_Excel(libro_excel, excel_name, sheet3, techniques, 'B2', f'K{len(technique_ids)+2}', technique_ids, columnas3)
        Write_Dic_to_Excel(libro_excel, excel_name, sheet4, subtechniques, 'B2', f'J{len(subtechnique_ids)+2}', subtechnique_ids, columnas4)
        # Cierra el archivo
        libro_excel.close()
    except FileNotFoundError:
        print(f"El archivo '{excel_name}' no se encontró.")
    except Exception as e:
        print(f"Ocurrió un error inesperado al escribir en excel: {e}")
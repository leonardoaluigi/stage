# Analisi automatizzata di Ransomware con CapeV2

`CapeV2.py` è uno script Python sviluppato per automatizzare l'analisi di campioni di ransomware tramite le API REST di CapeV2.

Lo script gestisce la sottomissione dei file, il controllo dello stato di esecuzione, la cattura del traffico di rete con `tcpdump`, la generazione dell'albero dei processi con Graphviz e l'estrazione degli indicatori di compromissione (file modificati, chiavi di registro, regole YARA e TTP MITRE).

### Famiglie di ransomware analizzate
L'analisi è stata eseguita su campioni reali di:
* Akira
* LockBit
* Rhysida
* MarLock (MedusaLocker)
* Dharma

I report completi, i PCAP di rete, i grafici dei processi e i file estratti sono disponibili per il download qui:  
[Archivio Google Drive](https://drive.google.com/file/d/1X0GIs_65M0Yuy5Qa5PMWjwGyyGsTmTS8/view)

La relazione completa del tirocinio è presente nel file `stage.pdf`.

<details>
<summary><b>English Version</b></summary>

# Automated Ransomware Analysis with CapeV2

`CapeV2.py` is a Python script developed to automate ransomware analysis using CapeV2's REST APIs.

The script handles sample submission, task status polling, network traffic dumps via `tcpdump`, process tree visualization using Graphviz, and the extraction of key Indicators of Compromise (modified files, registry changes, YARA detections, and MITRE TTPs).

### Analyzed Ransomware Families
The analysis was performed on real samples of:
* Akira
* LockBit
* Rhysida
* MarLock (MedusaLocker)
* Dharma

Complete analysis results, network PCAPs, process graphs, and generated reports can be downloaded here:  
[Google Drive Archive](https://drive.google.com/file/d/1X0GIs_65M0Yuy5Qa5PMWjwGyyGsTmTS8/view)

The full internship documentation is available in `stage.pdf`.

</details>

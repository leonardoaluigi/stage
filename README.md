# Analisi automatizzata di Ransomware con CapeV2

`CapeV2.py` è uno script Python sviluppato per automatizzare l'analisi di campioni di ransomware tramite le API REST di CapeV2[span_0](start_span)[span_0](end_span).

Lo script gestisce la sottomissione dei file, il controllo dello stato di esecuzione, la cattura del traffico di rete con `tcpdump`, la generazione dell'albero dei processi con Graphviz e l'estrazione degli indicatori di compromissione (file modificati, chiavi di registro, regole YARA e TTP MITRE)[span_1](start_span)[span_1](end_span).

### Famiglie di ransomware analizzate
L'analisi è stata eseguita su campioni reali di[span_2](start_span)[span_2](end_span):
* Akira[span_3](start_span)[span_3](end_span)
* LockBit[span_4](start_span)[span_4](end_span)
* Rhysida[span_5](start_span)[span_5](end_span)
* MarLock (MedusaLocker)[span_6](start_span)[span_6](end_span)
* Dharma[span_7](start_span)[span_7](end_span)

I report completi, i PCAP di rete, i grafici dei processi e i file estratti sono disponibili per il download qui:  
[Archivio Google Drive](https://drive.google.com/file/d/1X0GIs_65M0Yuy5Qa5PMWjwGyyGsTmTS8/view)

La relazione completa del tirocinio è presente nel file `stage.pdf`[span_8](start_span)[span_8](end_span).

<details>
<summary><b>English Version</b></summary>

# Automated Ransomware Analysis with CapeV2

`CapeV2.py` is a Python script developed to automate ransomware analysis using CapeV2's REST APIs[span_9](start_span)[span_9](end_span).

The script handles sample submission, task status polling, network traffic dumps via `tcpdump`, process tree visualization using Graphviz, and the extraction of key Indicators of Compromise (modified files, registry changes, YARA detections, and MITRE TTPs)[span_10](start_span)[span_10](end_span).

### Analyzed Ransomware Families
The analysis was performed on real samples of[span_11](start_span)[span_11](end_span):
* Akira[span_12](start_span)[span_12](end_span)
* LockBit[span_13](start_span)[span_13](end_span)
* Rhysida[span_14](start_span)[span_14](end_span)
* MarLock (MedusaLocker)[span_15](start_span)[span_15](end_span)
* Dharma[span_16](start_span)[span_16](end_span)

Complete analysis results, network PCAPs, process graphs, and generated reports can be downloaded here:  
[Google Drive Archive](https://drive.google.com/file/d/1X0GIs_65M0Yuy5Qa5PMWjwGyyGsTmTS8/view)

The full internship documentation is available in `stage.pdf`[span_17](start_span)[span_17](end_span).

</details>

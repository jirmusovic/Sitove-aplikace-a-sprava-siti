# ISA projekt - DHCP komunikace

## Jméno autora: Veronika Jirmusová
## Login: xjirmu00
### Datum vytvoření: 17.11.2023

Program monitoruje DHCP komunikaci (nebo ji přečte ze zadaného souboru) a poskytuje síťové  statistiky o vytížení síťových prefixů z pohledu alokovaných IP adres.

Program se překládá pomocí příkazu make a spouští se pomocí příkazové řádky příkazem 
<br> $./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ],$<br>
kde:

     - -r <filename>: statistika bude vytvořena z pcap souborů,
     - -i <interface>: rozhraní, na kterém může program naslouchat,
     - <ip-prefix>: Rozsah sítě pro které se bude generovat statistika.


### Seznam odevzdaných souborů:
Zdrojové soubory: main.cpp, argcheck.cpp, parser.cpp, pcap.cpp <br>
Hlavičkové soubory: argcheck.h, parser.h, pcap.h <br>
Dokumentace: manual.pdf, README.md, dhcp-stats.1 <br>
Makefile: Makefile

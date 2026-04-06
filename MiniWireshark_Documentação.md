# MiniWireshark — Documentação Técnica

**Projeto:** MiniWireshark-GRP | **Linguagem:** Python 3 | **Dependência principal:** Scapy 2.7.0 | **Plataforma alvo:** Raspberry Pi (Linux/POSIX) | **Ficheiro principal:** `main.py`

---

## 1. Visão Geral

O MiniWireshark é uma ferramenta de captura de pacotes de rede desenvolvida em Python que replica funcionalidades básicas do Wireshark. Foi desenhada para correr num Raspberry Pi, capturando tráfego em tempo real e enviando automaticamente os ficheiros de captura para o Google Drive via rclone.

O fluxo de execução é simples: o programa arranca, seleciona a interface de rede mais ativa, captura pacotes durante 180 segundos exibindo-os em tempo real na consola, guarda a captura num ficheiro .pcap e envia-o automaticamente para a cloud.

---

## 2. Pré-requisitos

O sistema requer um Raspberry Pi com Python 3 instalado, a biblioteca Scapy 2.7.0 e o rclone. A captura de pacotes exige privilégios de root, uma vez que o acesso a raw sockets em Linux não está disponível para utilizadores comuns. O programa deve ser executado com `sudo ./venv/bin/python main.py` para preservar o ambiente virtual.

---

## 3. Configuração do rclone

O upload é feito via rclone, com as credenciais e destino definidos no topo do `main.py`. O parâmetro `RCLONE_CONFIG` indica o caminho para o ficheiro de configuração do rclone no sistema e `RCLONE_REMOTE` define a pasta de destino no Google Drive (`gdrive:pcaps`). A configuração inicial é feita uma única vez através do comando `rclone config`, seguindo o assistente interativo de autenticação com a conta Google.

> **Nota:** o caminho do `rclone.conf` está definido para o utilizador `alezandrio` e deve ser ajustado conforme o utilizador ativo no Raspberry Pi.

---

## 4. Estrutura do Código — Funções Principais

**`main()`** — ponto de entrada. Exibe o banner, verifica os privilégios de root, seleciona a interface automaticamente e inicia a captura.

**`choose_interface_automatic()`** — realiza um scan de 3 segundos em cada interface disponível e seleciona automaticamente a que apresenta maior volume de tráfego.

**`choose_interface_by_command()`** — alternativa manual: apresenta um menu numerado com as interfaces disponíveis e permite ao utilizador escolher a pretendida.

**`capture_loop(iface)`** — núcleo funcional do programa. Inicia a captura na interface indicada e processa cada pacote em tempo real. A captura termina ao fim de 180 segundos, quando o utilizador prime `p` para aceder ao menu de configuração, ou com `Ctrl+C`.

**`packet_handler(packet)`** — formata cada pacote para exibição na consola, apresentando o timestamp, protocolo (TCP, UDP, ICMP, ARP, DNS, HTTP, TLS ou Raw), endereços IP de origem e destino, tamanho em bytes e porta de destino.

**`key_listener()`** — thread paralela que escuta o teclado em modo cbreak (sem buffer). Ao detetar a tecla `p`, sinaliza ao loop principal para parar e abrir o menu. Restaura sempre as definições originais do terminal ao terminar.

**`save_capture()`** — guarda os pacotes num ficheiro .pcap com o nome `capture_grp_<interface>_<timestamp>.pcap`, utilizando a função `wrpcap()` da Scapy, e invoca de seguida o upload.

**`upload_to_drive()`** — envia o ficheiro para o Google Drive via rclone. Em caso de falha, o ficheiro é preservado localmente e o utilizador é notificado com a mensagem de erro devolvida pelo rclone.

**`setup_menu()`** — menu de configuração com quatro opções: continuar a captura, mudar de interface manualmente, mudar de interface automaticamente, ou sair.

---

## 5. Ficheiros de Captura Gerados

Durante os testes foram gerados seis ficheiros na interface `wlp2s0`, com tamanhos entre 2,6 KB e 2,3 MB, consoante a duração e o volume de tráfego de cada sessão. Todos os ficheiros estão em formato PCAP e podem ser abertos diretamente no Wireshark para análise visual detalhada.

---

## 6. Considerações de Segurança

O programa requer root para aceder a raw sockets, pelo que deve ser utilizado com precaução em ambientes partilhados. O ficheiro `rclone.conf` contém as credenciais do Google Drive e deve ter permissões restritivas (`chmod 600`). Os ficheiros .pcap contêm tráfego de rede em texto claro e devem ser tratados como dados sensíveis. Por fim, a constante `RCLONE_REMOTE` encontra-se definida duas vezes no código — embora sem impacto funcional, recomenda-se a remoção da definição duplicada em versões futuras.

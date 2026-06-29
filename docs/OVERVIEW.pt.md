# Urban Hack Sentinel — Visão Geral do Projecto

Uma narrativa tecnicamente correcta e em linguagem simples sobre por que este projecto existe, o que ele faz e para quem ele serve.

---

## O nome

**Urban** — o projecto foca-se nas tecnologias que se encontram nas cidades: redes Wi-Fi, dispositivos Bluetooth, câmaras inteligentes, gadgets IoT e brokers MQTT. Não se trata de equipamento militar obscuro; é o `wlan0` de uma café, o beacon BLE num pára-brisas de autocarro, a câmara IP acima de uma loja.

**Hack** — não no sentido cinematográfico. Aqui significa: entender como algo funciona tomando-o como referência, testando os seus pressupostos e documentando o que falha. O projecto ataca redes e protocolos, mas só para mostrar que elas se quebram de forma previsível e reproduzível.

**Sentinel** — o sistema foi concebido para funcionar sem supervisão contínua. Um Raspberry Pi numa mochila, alimentado por uma powerbank, a varrer enquanto caminhas pela cidade. Vigiando. Registando. A informar. O operador não precisa de acompanhar cada passo.

---

## Como começou

Este projecto começou com uma pergunta: *quão fácil é quebrar as redes sem fios que as pessoas usam todos os dias?*

Em 2024, durante os estudos em Cibersegurança na FEUP, testei uma hipótese. Coloquei um Raspberry Pi, um adaptador Wi-Fi Alfa AWUS036ACH, uma powerbank e um receptor GPS numa mochila. Caminhei pela Avenida da Boavista, no Porto, a fazer scan de redes Wi-Fi e a capturar handshakes WPA/WPA2. O resultado foi inquietante. Numa única tarde recolhi chaves de redes que as pessoas assumem como privadas, usando menos de €150 em hardware e nenhuma habilidade especial além do que qualquer pessoa pode aprender em documentação pública.

Esse experimento originou uma série de perguntas:

- O que acontece quando o WPA3 encontra uma implementação defeituosa?
- Um dispositivo Bluetooth pode ser impersonado sem que o dono perceba?
- As câmaras "inteligentes" montadas nas ruas ainda usam credenciais por defeito?
- Quais os CVEs ainda exploráveis em 2026, e quais são apenas ruído?

Em vez de correr comandos `aircrack-ng` isolados à mão, comecei a construir uma framework estruturada. O objectivo não era apenas recolher dados, mas tornar o processo reproduzível, modular e partilhável. Essa framework tornou-se o **Urban Hack Sentinel**.

---

## O que faz

O Urban Hack Sentinel é uma plataforma modular de auditoria para tecnologias wireless, Bluetooth, IoT e rede comuns em ambientes urbanos. Corre num Raspberry Pi ou em qualquer máquina x86/64 com Linux e expõe três interfaces:

- **CLI** (`urban-hs`) — para scripting e automação.
- **TUI** (`urban-hs-tui`) — um dashboard full-screen em Textual para operação em tempo real no terreno.
- **Dashboard Web** (`urban-hs-server`) — uma API REST + WebSocket + interface browser para monitorização remota ou integração com outras ferramentas.

No núcleo, cada capacidade é um plugin: scanning Wi-Fi, captura PMKID, ataques WPS, BLE Fast Pair / WhisperPair, scans Nmap, RPC Metasploit, descoberta de câmaras, injecção HID, brute force MQTT, entre outros. Novos plugins podem ser adicionados sem tocar na framework principal.

O sistema foi concebido para **operação contínua**. Descobre hardware automaticamente (HAL — Hardware Abstraction Layer), selecciona o melhor backend (`iw`, `scapy`, `bleak`, `nmap`, etc.) e transmite eventos através de um event bus interno. A UI reage em tempo real.

---

## O caminho de aprendizagem

Isto não é um produto acabado. É um **veículo de aprendizagem**.

Sou estudante. Apreendo fazendo. Cada módulo no projecto corresponde a uma tecnologia que eu queria entender:

- Implementei o módulo Wi-Fi porque queria ver como canais e isolamento de clientes se comportam na prática.
- Adicionei ataques Bluetooth HID depois de ler o CVE-2023-45866 e o CVE-2024-21306.
- Integrei o Metasploit RPC porque queria passar de invocações isoladas de `msfconsole` para uma gestão estruturada de sessões.
- Adicionei a HAL e os builds Docker multi-arquitectura para aprender como software se adapta a hardware diferente sem bifurcar o repositório.

Quando fico bloqueado, delego decisões de implementação a um assistente AI. Revisto o código, aprendo com ele, e itero. Este documento faz parte desse ciclo: explicar o projecto com clareza obriga-me a entendê-lo eu próprio.

---

## A quem serve

O projecto é deliberadamente vasto no público-alvo.

**Iniciantes em cibersegurança** podem usar a UI existente como forma segura e guiada de correr scans e ver resultados. A tabela de capacidades no README explica o que cada módulo faz antes de eles escreverem um único comando.

**Operadores experientes** podem escrever plugins custom. A API de plugins está documentada, o event bus é tipado e a HAL abstrai particularidades de hardware para eles se concentrarem na lógica do ataque, não na detecção de plataforma.

**Estudantes e investigadores** podem usar o código como referência. A estrutura modular mostra como organizar um projecto Python com tratamento assíncrono de eventos, descoberta de plugins, abstracção de hardware e múltiplas camadas de apresentação a partir de uma única base de código.

**Leitores não-técnicos** podem ler esta visão geral e compreender o modelo de ameaça: que tecnologias comuns de consumo têm falhas, que essas falhas são reproduzíveis, e que a consciencialização é o primeiro passo para escolher alternativas mais seguras.

---

## Modelo de ameaça e ética

Os ataques do Urban Hack Sentinel só devem ser executados **em redes e dispositivos que você possui ou tem autorização explícita para auditar**. Esta não é uma ferramenta de zona cinzenta. Usá-la contra infra-estrutura que não lhe pertence é ilegal na maioria das jurisdições e contradiz os princípios do projecto.

A plataforma foi desenhada para ser **observável**. Toda a acção passa pelo event bus. Todo o plugin pode ser auditado. Executar com `dry_run=true` executa a lógica do plugin sem tocar ao hardware, que é o modo recomendado para aprender e demonstrar.

---

## Estado actual

Em meados de 2026, as **fases 0–10** estão concluídas no branch `andreas/catarinus`:

- Core: event bus, configuração, armazenamento e registo de plugins.
- HAL para Wi-Fi (`iw` + fallback `scapy`) e Bluetooth (`bleak`).
- Módulos para Wi-Fi, BLE, scanning de rede, Metasploit, HID, MQTT, câmaras e manipulação de credenciais.
- Interfaces CLI, TUI e web ligadas ao mesmo backend.
- API REST com inventário e endpoints de execução de ataques.
- Stream de eventos WebSocket padronizado para `attack.started`, `attack.progress`, `attack.completed` e `attack.error`.
- Plugins de exemplo e um módulo de relatórios tipo Ghostwriter.
- Builds Docker multi-arquitectura (`linux/amd64`, `linux/arm64`).
- Suite de testes cobrindo HAL, API, CLI, contratos de eventos e smoke tests da TUI.

O que vem a seguir depende do que preciso aprender de seguida: validação em hardware real com Alfa AWUS036ACH e Pi 5, integração mais profunda com Metasploit, mapas de wardriving com GPS, ou publicação de templates de módulos para a comunidade.

---

## Filosofia de design

1. **Um código, muitas interfaces.** A CLI, a TUI e a web partilham o mesmo backend. Adicionar uma funcionalidade uma vez torna-a disponível em todos os lados.
2. **Hardware é um plugin.** A HAL permite que o mesmo ataque corra num Pi com adaptador Alfa, num portátil x86 com Intel AX210, ou numa VM de cloud com interfaces virtuais mockadas para CI.
3. **Eventos em vez de polling.** A UI não pergunta "já acabaste?" a cada segundo. O backend empurra o progresso pelo event bus e a UI renderiza-o.
4. **Extensibilidade por convenção.** Para adicionar um módulo novo, cria-se uma classe, regista-se e emite-se eventos padrão. Não é necessário alterar routers, código de UI ou camadas de armazenamento.
5. **Transparência em vez de obscurantismo.** Tudo o que toca em hardware é registado, estruturado e capturável. Não existem chamadas `os.system` silenciosas que desaparecem no vazio.

---

## Agradecimentos

Este projecto existe porque a FEUP obriga os alunos a aprender construindo, porque investigadores de segurança open-source documentam CVEs e exploits publicamente, e porque ferramentas de desenvolvimento assistidas por IA permitem que um único estudante itere mais depressa do que seria possível há cinco anos.

Se estás a ler isto e também estás a aprender: constrói alguma coisa. Quebra-a. Documenta por que é que ela quebrou. Esse é o único caminho que realmente fica.

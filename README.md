# 🛡️ Building a SOC Home Lab: Detection & Response Project

Este projeto documenta a construção de um Laboratório de Security Operations Center (SOC) para simular ataques reais e praticar Defesa Cibernética (Blue Team). O objetivo é implementar uma stack completa de monitoramento (ELK), ingerir logs de endpoints e desenvolver habilidades de detecção e resposta a incidentes.

## 📌 Fase 1: Arquitetura e Infraestrutura 

### 1. Arquitetura Lógica
Antes do deploy, foi desenhada a topologia da rede para entender o fluxo de dados e posicionamento dos sensores. O laboratório simula um ambiente corporativo real contendo:

![Topologia de Rede](images/00-network-topology.png)
*Diagrama da arquitetura do laboratório desenhado durante o planejamento.*
* **VPC (Virtual Private Cloud):** Para isolamento da rede.
* **SIEM (ELK Stack):** O coração do monitoramento.
* **Endpoints (Windows/Linux):** Alvos que serão monitorados e atacados.
* **C2 Server (Command & Control):** Para simular o atacante externo.

### 2. Provisionamento de Infraestrutura (IaaS)
Utilizei a **Vultr** como provedor de nuvem. A escolha foi baseada na capacidade de configurar redes privadas personalizadas e baixo custo.

**Configurações do Servidor SIEM:**
* **OS:** Ubuntu 22.04 LTS (Estabilidade e suporte da comunidade).
* **Specs:** 2 vCPU, 8GB RAM (Dimensionado para suportar a JVM do Elasticsearch).
* **Região:** Toronto (Para garantir compatibilidade de latência com a VPC).

![Status da VM e Specs](images/01-infrastructure-deploy.png)
*Deploy da instância Ubuntu Server concluído e rodando.*

### 3. Configuração de Rede e Segurança (Hardening)
A segurança do próprio laboratório foi uma prioridade. Não expus o servidor diretamente sem proteções.

* **VPC Network:** Criei uma rede privada isolada para que os agentes (futuros servidores Windows/Linux) se comuniquem com o SIEM sem trafegar logs sensíveis pela internet pública.
* **Firewall na Nuvem:** Implementei um *Firewall Group* na Vultr seguindo o princípio do menor privilégio.
    * **Porta 22 (SSH):** Restrita apenas ao meu IP atual de gerenciamento.
    * **Porta 9200 (Elasticsearch):** Restrita ao meu IP e à rede interna da VPC.

![Regras de Firewall](images/02-firewall-hardening.png)
*Aplicação de regras de firewall restringindo acesso SSH e TCP/9200.*

### 4. Instalação e Configuração do Elasticsearch
Realizei a instalação manual do Elasticsearch via repositório APT oficial, garantindo a versão mais recente e segura.

**Credenciais e Segurança Inicial:**
Durante a instalação, o Elasticsearch gerou automaticamente os tokens de segurança e a senha do superusuário, garantindo que o banco de dados já nasça autenticado.

![Instalação e Senhas](images/03-elasticsearch-install.png)
*Output de segurança pós-instalação com credenciais geradas.*

**Ajustes de Configuração (`elasticsearch.yml`):**
Para permitir que o servidor receba conexões externas (do meu laptop de analista e dos agentes), precisei alterar as configurações de *binding* de rede, saindo do padrão `localhost`.

![Configuração Nano](images/04-config-yaml.png)
*Edição do arquivo YAML definindo o host de rede público e a porta padrão 9200.*

**Status do Serviço:**
Após a configuração e recarga dos *daemons*, o serviço subiu com sucesso e está ativo.

![Status Active](images/05-service-active.png)
*Validação do serviço rodando via SystemD.*

---

### ⚠️ Desafios e Soluções (Troubleshooting)

Durante essa fase inicial, enfrentei desafios técnicos reais de ambiente Cloud que exigiram adaptação:

**1. Cota de Recursos na Cloud (Resource Quotas)**
Ao tentar provisionar a máquina de 16GB, fui bloqueada pela política de cota para novas contas ("Monthly Fee Limit Reached").

![Erro de Cota](images/99-troubleshooting-quota.png)
*Erro de limite de provisionamento encontrado.*

* **Solução:** Realizei o *downsizing* estratégico para uma instância de 8GB RAM e otimizei o servidor. Isso permitiu continuar o laboratório dentro do orçamento e das limitações da conta, sem perder funcionalidade crítica.

**3. IP Dinâmico (CGNAT)**
Meu provedor de internet altera o IP frequentemente, o que bloqueava meu acesso às regras restritas do Firewall.
* **Solução:** Aprendi a monitorar meu IP público e atualizar as regras de *Ingress* dinamicamente. Para testes de conectividade rápida, gerenciei o risco temporariamente via regras "Anywhere" combinadas com a autenticação forte nativa do Elastic.

---

## 📌 Fase 2: Visualização de Dados com Kibana 

Com o backend de logs (Elasticsearch) funcional, o próximo passo foi implementar o **Kibana**, a interface gráfica que permitirá a visualização dos dados, criação de dashboards e investigação de alertas de segurança.

### 1. Instalação e Exposição do Serviço
O Kibana foi instalado no mesmo servidor Ubuntu. Diferente do Elasticsearch (Backend), o Kibana precisa ser acessível via navegador.

**Configuração de Rede (`kibana.yml`):**
Editei o arquivo de configuração para alterar o `server.host`. Por padrão, ele vem travado em `localhost`. Configurei para ouvir no IP público do servidor, permitindo o acesso remoto à interface web na porta padrão `5601`.

![Configuração Kibana](images/06-kibana-config-yaml.png)
*Ajuste do binding de rede para permitir acesso externo à interface web.*

**Validação do Serviço:**
Após a configuração, o serviço foi iniciado e verificado via SystemD para garantir que não houvesse erros de *bootstrap*.

![Status do Serviço](images/07-kibana-service-status.png)
*Serviço do Kibana ativo e rodando (Active/Running).*

### 2. Conexão Segura (Enrollment Token)
Para conectar o Kibana ao Elasticsearch de forma segura, utilizei o mecanismo de **Enrollment Tokens**. Isso garante que a comunicação entre a interface e o banco de dados seja autenticada e criptografada, prevenindo interceptação de dados.

![Geração de Token](images/08-security-enrollment.png)
*Geração do token de inscrição para pareamento seguro entre Kibana e Elasticsearch.*

### 3. Acesso e Configuração de Criptografia (Keystore)
Após o login inicial, obtive acesso à interface central do Elastic ("Welcome Home"), confirmando que a stack ELK estava operacional.

![Elastic Home](images/10-elastic-home-welcome.png)
*Acesso bem-sucedido à interface web do Elastic Stack.*

**Troubleshooting: Erro de Permissões e Chaves de Criptografia**
Ao navegar para a aba de **Security > Alerts**, deparei-me com um erro de sistema: *"Detection engine permissions required"*.
Investigando a documentação, identifiquei que o erro não era de permissões de utilizador, mas sim a ausência de chaves de criptografia no *Keystore* do Kibana, necessárias para armazenar regras de alerta de forma segura.

![Erro Encryption](images/97-troubleshooting-encryption-error.png)
*Erro apresentado devido à falta de chaves de criptografia persistentes.*

**Solução Aplicada:**
1.  Gerei novas chaves de criptografia via CLI (`kibana-encryption-keys generate`).
2.  Adicionei as chaves manualmente ao cofre seguro do Kibana (`kibana-keystore add`).
3.  Reiniciei o serviço para aplicar as alterações.

![Gerando Chaves](images/11-generating-encryption-keys.png)
*Geração e inserção das chaves de segurança no Keystore.*

**Resultado Final:**
O painel de Alertas carregou com sucesso, pronto para receber deteções de segurança.

![Alerts Corrigido](images/12-alerts-dashboard-fixed.png)
*Painel de Security Alerts totalmente operacional após a correção.*

---

### ⚠️ Desafios e Soluções (Troubleshooting)

**1. Bloqueio de Firewall e Portas Reservadas**
Ao tentar acessar a interface web (`http://IP:5601`), recebi erros de *Connection Timed Out*. Diagnostiquei que o Firewall da Cloud (Vultr) estava bloqueando a porta 5601.
Ao tentar liberar o tráfego TCP, cometi um erro ao definir o range de portas iniciando em `0` (`0-65535`), o que foi rejeitado pela plataforma.

![Erro Firewall](images/98-troubleshooting-firewall-error.png)
*Erro ao tentar configurar regra de firewall com porta inválida (0).*

* **Solução:** Ajustei a regra para um range válido (`1-65535`) e configurei o acesso temporário para `Anywhere` (0.0.0.0/0) para fins de teste de conectividade, liberando o acesso ao painel do Kibana.

![Firewall Corrigido](images/09-firewall-fixed-kibana.png)
*Regra de firewall corrigida permitindo tráfego TCP na porta do Kibana.*

---

## 📌 Fase 3: Vítima e Hardening 

Para simular um cenário real de ataque, provisionei um servidor Windows Server 2022 exposto à internet. Este servidor atuará como o *endpoint* monitorado e alvo das simulações de ataque.

### 1. Arquitetura de Segurança (Isolamento)
Diferente dos componentes do SIEM (ELK), decidi **não** conectar o servidor Windows à VPC (Rede Privada).
* **Objetivo:** Garantir isolamento total (Network Segmentation). Caso o servidor Windows seja comprometido por um atacante real (o que é esperado, dado que exporemos RDP), o atacante não terá rota de rede lateral para alcançar meu servidor de logs (Ubuntu/Elasticsearch).

![Specs Windows](images/13-windows-isolation-specs.png)
*Provisionamento do Windows Server 2022 fora da VPC para quarentena de rede.*

### 2. Acesso e Configuração Inicial
O acesso inicial foi realizado via Console VNC (NoVNC) provido pela plataforma de nuvem para garantir que o sistema operacional completou o *boot* corretamente antes de expor serviços de rede.

![Console Boot](images/14-windows-console-boot.png)
*Boot inicial e login administrativo via Console Web.*

### 3. Exposição Controlada (RDP)
Habilitei o protocolo RDP (Remote Desktop Protocol - Porta 3389) para administração remota.
* **Risco Aceito:** Manter o RDP exposto na internet é uma vulnerabilidade crítica comum. Neste laboratório, isso é intencional para gerar logs de *Brute Force* reais que serão capturados e analisados pelo SIEM nas próximas etapas.

![Acesso RDP](images/15-windows-rdp-access.png)
*Conexão remota bem-sucedida provando a acessibilidade pública do alvo.*

---
## 📌 Fase 4: Ingestão de Dados e Fleet Server 

Com a infraestrutura do SIEM (ELK) e da Vítima (Windows) prontas, a próxima etapa foi conectá-los. Para isso, utilizei a arquitetura **Elastic Fleet**, que centraliza o gerenciamento de todos os agentes de coleta.

Esta fase exigiu a criação de uma terceira VM Linux (`MyDFIR-Fleet-Server`) para atuar como o "Gerente" dos agentes, seguindo as boas práticas de separação de funções.

![Specs Fleet Server](images/16-fleet-server-deploy-specs.png)
*Provisionamento da VM dedicada para o Fleet Server.*

---

### ⚠️ Desafios e Soluções (Troubleshooting Avançado)

Esta foi a fase mais complexa do projeto até o momento, apresentando múltiplos pontos de falha que exigiram diagnóstico em diferentes camadas (Rede, Aplicação e Configuração).

#### 1. Troubleshooting (Linux): Firewall e Conectividade
Ao tentar instalar o Fleet Server (agente Linux), a instalação falhou com erros de `i/o timeout`.

![Erro de Conexão](images/17-troubleshoot-linux-firewall-error.png)
*Log de erro indicando que o Fleet Server não conseguia se comunicar com o Elasticsearch na porta 9200.*

* **Diagnóstico:** O Firewall Group da Vultr, configurado para aceitar conexões apenas do "Meu IP", estava bloqueando a comunicação interna entre os servidores (Fleet não conseguia falar com ELK).
* **Solução:** Alterei a regra de firewall para `Anywhere (0.0.0.0/0)` para o range `1-65535`, permitindo a comunicação interna necessária para o laboratório. Isso resolveu o bloqueio das portas **9200** (Elastic) e **8220** (Fleet).

![Firewall Fix](images/18-vultr-firewall-fix.png)
*Ajuste nas regras de firewall para permitir a comunicação interna do lab.*

Após a correção do firewall, a instalação do Fleet Server no Linux foi concluída com sucesso.

![Sucesso Linux](images/19-linux-agent-install-success.png)
*Instalação do agente Fleet Server bem-sucedida.*

#### 2. Troubleshooting (Windows): Instalação do Agente
A implantação do agente no Windows Server apresentou três erros em sequência:
1.  **Erro de PowerShell:** O comando copiado do Kibana era longo e quebrava linhas, fazendo o PowerShell executá-lo incorretamente.
2.  **Erro de Caminho:** O PowerShell não encontrava o `elastic-agent.exe` pois eu não estava no diretório correto.
3.  **Erro de Loop (`:443`):** O agente instalava, mas entrava em loop infinito de conexão.

* **Solução (Comando Final):** Resolvi todos os problemas de uma vez construindo um comando de instalação manual e robusto.
    1.  Naveguei para o diretório correto (`cd elastic-agent...`).
    2.  Usei o IP e a porta **correta** (`:8220`).
    3.  Adicionei a flag `--force` para sobrescrever a instalação anterior falha.

![Sucesso Windows](images/20-windows-agent-install-success.png)
*Comando final no PowerShell (com `cd` e `--force`) que resultou na instalação bem-sucedida.*

#### 3. Troubleshooting (Kibana): O Loop "Updating"
Após a instalação, o agente Windows ficou preso no status "Updating".
* **Diagnóstico:** Ao inspecionar a mensagem de erro no Kibana, notei que o agente tentava se comunicar na porta `:443`, apesar de eu ter forçado a instalação na `:8220`. A **Política de Agente** (Agent Policy) no Kibana estava configurada com a URL errada, sobrescrevendo minha instalação manual.

![Erro de Política](images/21-troubleshoot-kibana-policy-error.png)
*Configuração do Fleet Server no Kibana apontando para a porta errada (443).*

* **Solução Definitiva:** Editei as configurações do Fleet Server diretamente no Kibana, corrigindo a URL global para `https://[IP_DO_FLEET]:8220`. Após reiniciar o serviço no Windows (`Stop-Service/Start-Service`), o agente recebeu a política correta.

### 4. Validação Final da Infraestrutura
Com todas as correções aplicadas, ambos os agentes (Linux Fleet Server e Windows Vítima) reportaram status **Healthy** (Saudável), confirmando que a infraestrutura de coleta de logs está 100% operacional.

![Dashboard Fleet](images/22-fleet-dashboard-all-healthy.png)
*Visão final do painel Fleet com todos os agentes online e saudáveis.*

---
## 📌 Fase 5: Enriquecimento de Logs com Sysmon 

Com os agentes online, o próximo passo foi enriquecer a qualidade dos dados coletados. O Elastic Agent coleta os logs de segurança padrão do Windows, mas para uma detecção de ameaças eficaz (Threat Hunting), é necessária uma telemetria mais profunda.

Para isso, instalei o **Sysmon (System Monitor)** da Microsoft, a ferramenta padrão da indústria para monitoramento avançado de *endpoints*.

### 1. Instalação e Configuração
A instalação foi realizada no servidor Windows Server (Vítima). O ponto crucial foi não instalar o Sysmon com as configurações padrão (que são muito "barulhentas").

Utilizei uma configuração personalizada (`.xml`) baseada no projeto *SwiftOnSecurity*, que é um padrão de mercado. Este arquivo filtra eventos de sistema irrelevantes e foca no que é importante para a segurança, otimizando a ingestão de dados no SIEM.

![Instalação Sysmon](images/23-sysmon-install-powershell.png)
*Instalação do Sysmon via PowerShell (Admin), aplicando o arquivo de configuração .xml.*

### 2. Validação Local
Após a instalação, validei que o Sysmon estava operacional na própria máquina antes de tentar configurá-lo no SIEM.

**1. Verificação do Serviço:**
Confirmei que o serviço `Sysmon64` foi instalado e estava em execução (`Running`) no `services.msc`.

![Serviço Sysmon](images/24-sysmon-service-running.png)
*Serviço Sysmon64 ativo e rodando em segundo plano.*

**2. Verificação dos Logs:**
Confirmei no **Visualizador de Eventos (Event Viewer)** que os logs estavam sendo gerados. Isso prova que o Sysmon está monitorando ativamente o sistema.

![Logs Sysmon Locais](images/25-sysmon-local-event-viewer.png)
*Logs operacionais do Sysmon (ex: Event ID 3 - Network connection) sendo gerados localmente.*

---
## 📌 Fase 6: Ingestão de Logs no SIEM 

Com o Sysmon a gerar logs localmente, o passo final da infraestrutura foi configurar o *Elastic Agent* para ler esses arquivos e enviá-los para o Elasticsearch.

### 1. Integração de Fontes de Dados (Data Ingestion)
No Kibana, configurei a política do agente Windows para incluir duas novas integrações de **"Custom Windows Event Logs"**. Isso instrui o agente a ler canais específicos do Windows Event Viewer.

**Canais Configurados:**
* **Sysmon:** `Microsoft-Windows-Sysmon/Operational` (Foco em criação de processos e rede).
* **Windows Defender:** `Microsoft-Windows-Windows Defender/Operational` (Foco em deteção de malware).

![Config Sysmon](images/26-integration-sysmon-config.png)
*Configuração do canal de ingestão para logs do Sysmon.*

![Config Defender](images/27-integration-defender-config.png)
*Configuração do canal de ingestão para logs do Windows Defender.*

### 2. Validação de Recebimento (Data Discovery)
Após aplicar a política, aguardei a propagação para o agente e validei o recebimento dos dados na aba **Discover** do Kibana.

Realizei testes gerando atividade no servidor (como reiniciar serviços de segurança) para confirmar que os logs estavam a chegar quase em tempo real.

**Resultado:**
Os logs do Sysmon (ex: *Process Create*, Event ID 1) e do Defender começaram a ser indexados corretamente pelo SIEM.

![Logs Sysmon](images/29-discover-sysmon-logs.png)
*Prova de ingestão: Log detalhado do Sysmon visualizado no Kibana.*

![Volume de Dados](images/30-discover-event-volume.png)
*Gráfico de volume de eventos confirmando o fluxo contínuo de dados entre a Vítima e o SIEM.*

---
## 📌 Fase 7: Criação de Honeypot SSH e Análise de Ataques (Dia 12)

O objetivo desta fase era provisionar um servidor Linux exposto à internet para atuar como "isca" (Honeypot) e capturar tentativas reais de ataque SSH (Brute Force).

### 1. Otimização de Recursos (Engenharia)
Durante o provisionamento de uma quarta instância (Linux Target), atingi o limite de cota da conta de nuvem (Cloud Resource Quotas).

![Decisão de Recurso](images/31-resource-optimization-decision.png)
*Limite de instâncias atingido durante a tentativa de scale-out.*

* **Solução Arquitetural:** Em vez de solicitar aumento de cota (o que geraria custos), optei por reutilizar o servidor `MyDFIR-Fleet-Server`. Como ele já é um servidor Linux Ubuntu exposto à internet (necessário para os agentes remotos), ele serve perfeitamente como alvo duplo: **Gerenciador de Agentes** e **Honeypot SSH**.

### 2. Análise de Logs de Autenticação (`auth.log`)
Acessando o servidor via SSH, analisei os logs de autenticação localizados em `/var/log/auth.log`.
Em pouco mais de 24 horas de exposição à internet, o servidor registrou centenas de tentativas de acesso não autorizado vindas de múltiplos endereços IP globais.

**Evidências de Ataque:**
Os logs mostram bots tentando adivinhar senhas para usuários comuns (`root`, `admin`) e serviços específicos (`git`, `composer`, `squid`).

![Logs de Ataque](images/32-ssh-bruteforce-evidence.png)
*Live logs demonstrando tentativas massivas de Brute Force contra o servidor exposto.*

---
## 📌 Fase 8: Ingestão de Logs Linux e Monitoramento SSH (Dia 13)

Com o servidor Linux ("Honeypot") sob ataque constante, configurei o agente para coletar esses logs e enviá-los para o SIEM, permitindo análise centralizada.

### 1. Configuração da Integração de Sistema
Como o *Fleet Server* já possuía o Elastic Agent instalado, precisei apenas validar a política de agentes. Confirmei que a integração **System** estava ativa e configurada para ler os logs de autenticação do sistema operacional.

* **Caminho do Log:** `/var/log/auth.log` (Padrão Ubuntu/Debian).
* **Dataset:** `system.auth`.

![Configuração Linux](images/33-linux-system-integration-config.png)
*Configuração da política para coleta de logs de autenticação (auth.log).*

### 2. Visualização de Ataques em Tempo Real
No Kibana, utilizei a funcionalidade **Discover** para filtrar eventos do dataset `system.auth` com resultado de falha (`event.outcome: failure`).

**Resultado:**
Os ataques de força bruta que antes eram apenas linhas de texto no terminal agora são eventos estruturados no SIEM. O gráfico de volume mostra a persistência dos ataques ao longo do tempo.

![Discover SSH](images/34-kibana-discover-ssh-failures.png)
*Visualização no Kibana confirmando a ingestão contínua de falhas de login SSH vindas da internet.*

---

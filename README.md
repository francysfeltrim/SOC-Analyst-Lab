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
**Próximos Passos:** Instalação do Kibana e Visualização de Dados.

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
**Próximos Passos:** Provisionamento do Servidor Windows (Vítima).

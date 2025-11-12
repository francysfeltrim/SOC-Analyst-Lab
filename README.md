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

**2. VPC 2.0 vs VPC Networks**
O tutorial original referenciava uma tecnologia depreciada (VPC 2.0).
* **Solução:** Migrei para a nova arquitetura de "VPC Networks" da Vultr, garantindo que a região fosse idêntica à da VM (Toronto) para haver conectividade entre os segmentos de rede.

**3. IP Dinâmico (CGNAT)**
Meu provedor de internet altera o IP frequentemente, o que bloqueava meu acesso às regras restritas do Firewall.
* **Solução:** Aprendi a monitorar meu IP público e atualizar as regras de *Ingress* dinamicamente. Para testes de conectividade rápida, gerenciei o risco temporariamente via regras "Anywhere" combinadas com a autenticação forte nativa do Elastic.

---
**Próximos Passos:** Instalação do Kibana e Visualização de Dados.

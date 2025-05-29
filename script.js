document.addEventListener('DOMContentLoaded', () => {
    const topicProbabilities = {
        CONCEITOS_FUNDAMENTAIS: { level: 'HIGH', colorVarSuffix: 'high' },
        CONTROLES_SEGURANCA:    { level: 'HIGH', colorVarSuffix: 'high' },
        AMEACAS_CRITICAS:       { level: 'HIGH', colorVarSuffix: 'high' },
        GESTAO_RISCO_CRITICA:   { level: 'HIGH', colorVarSuffix: 'high' },
        NORMAS_CRITICAS:        { level: 'HIGH', colorVarSuffix: 'high' },
        AMEACAS_ESPECIFICAS:    { level: 'MEDIUM', colorVarSuffix: 'medium' },
        NORMAS_SEGURANCA:       { level: 'MEDIUM', colorVarSuffix: 'medium' },
        GESTAO_RISCO:           { level: 'MEDIUM', colorVarSuffix: 'medium' },
        GESTAO_CONTINUIDADE:    { level: 'LOW', colorVarSuffix: 'low' }
    };

    const baseFixedQuestions = [
        {
            qIdPrefix: `bfq_`, stableId: `BFQ_CONCEITOS_01_FCC10`, topicKey: 'CONCEITOS_FUNDAMENTAIS',
            originalQNumberDisplay: `1`, highlight: true, sourceRef: `[Fonte: ATIVIDADES PDF, p. 1, Q1]`,
            text: `(FCC/2010) Sobre segurança da informação, considere:<br><strong>I.</strong> Ameaça: algo que possa provocar danos...<br><strong>II.</strong> Vulnerabilidade: é medida pela probabilidade...<br><strong>III.</strong> Risco: ponto pelo qual alguém pode ser atacado...<br>Está correto o que consta APENAS em:`,
            options: [ { text: `II e III`, id: `A`, isCorrect: false }, { text: `I e II`, id: `B`, isCorrect: false }, { text: `I e III`, id: `C`, isCorrect: false }, { text: `I`, id: `D`, isCorrect: true },  { text: `III`, id: `E`, isCorrect: false } ],
            gabaritoComentado: `Ameaça (I) está correta. Vulnerabilidade e Risco estão com conceitos trocados em II e III.`
        },
        {
            qIdPrefix: `bfq_`, stableId: `BFQ_AMEACAS_01_UFPB19`, topicKey: 'AMEACAS_CRITICAS',
            originalQNumberDisplay: `5`, highlight: true, sourceRef: `[Fonte: Prova AV.pdf, p. 3, Q5]`,
            text: `(UFPB/2019-Adaptada) ...O Phishing é um tipo de ameaça virtual... Em relação ao Phishing, assinale a alternativa correta.`,
            options: [ { text: `É o termo usado para se referir aos e-mails não solicitados...`, id: `A`, isCorrect: false }, { text: `São programas especificamente desenvolvidos para executar ações danosas...`, id: `B`, isCorrect: false }, { text: `É um software projetado para monitorar as atividades de um sistema...`, id: `C`, isCorrect: false }, { text: `São programas, ou parte de um programa de computador, normalmente maliciosos...`, id: `D`, isCorrect: false }, { text: `É um método de envio de mensagens eletrônicas que tentam se passar pela comunicação oficial...`, id: `E`, isCorrect: true } ],
            gabaritoComentado: `Phishing usa mensagens falsas para obter informações confidenciais.`
        },
        {
            qIdPrefix: `bfq_`, stableId: `BFQ_GESTAO_RISCO_01_AV`, topicKey: 'GESTAO_RISCO_CRITICA',
            originalQNumberDisplay: `6`, highlight: true, sourceRef: `[Fonte: Prova AV.pdf, p. 5, Q6]`,
            text: `Assinale a opção correta a respeito de segurança da informação, análise de riscos e medidas de segurança física e lógica.`,
            options: [ { text: `Analisar riscos consiste em enumerar todos os tipos de risco...`, id: `A`, isCorrect: true }, { text: `Em análises de riscos... desconsideram-se os possíveis efeitos...`, id: `B`, isCorrect: false }, { text: `As medidas de segurança dividem-se em dois tipos: as preventivas e as corretivas.`, id: `C`, isCorrect: false }, { text: `Como medida de segurança corretiva utilizam-se firewalls e criptografia.`, id: `D`, isCorrect: false }, { text: `Como medida de segurança preventiva utilizam-se controle de acesso lógico e sessão de autenticação.`, id: `E`, isCorrect: false } ],
            gabaritoComentado: `A análise de riscos completa envolve identificar riscos, consequências e perdas.`
        },
        {
            qIdPrefix: `bfq_`, stableId: `BFQ_CONTROLES_01_ATIV`, topicKey: 'CONTROLES_SEGURANCA',
            originalQNumberDisplay: `7`, highlight: true, sourceRef: `[Fonte: ATIVIDADES PDF, p. 13, Q7 Simulados / simulados.pdf, p.9, Q3]`,
            text: `Redes de computadores conectadas à internet são alvos de invasões por parte de hackers. A ferramenta para permitir o acesso à rede apenas por endereços autorizados é:`,
            options: [ { text: `Criptografia.`, id: `A`, isCorrect: false }, { text: `Firewall.`, id: `B`, isCorrect: true }, { text: `Certificado digital.`, id: `C`, isCorrect: false }, { text: `Antivírus.`, id: `D`, isCorrect: false }, { text: `Modem.`, id: `E`, isCorrect: false } ],
            gabaritoComentado: `Firewall controla o tráfego de rede baseado em regras, permitindo ou bloqueando acessos com base em endereços e outras políticas.`
        },
        {
            qIdPrefix: `bfq_`, stableId: `BFQ_GESTAO_RISCO_02_AV`, topicKey: 'GESTAO_RISCO_CRITICA',
            originalQNumberDisplay: `8`, highlight: true, sourceRef: `[Fonte: Prova AV.pdf, p. 6, Q8]`,
            text: `O risco residual é assim classificado quando não se tem uma resposta adequada ao risco, ou ele é considerado mínimo. Mesmo assim, deve passar pela etapa de:`,
            options: [ { text: `Comunicação e consulta do risco.`, id: `A`, isCorrect: false }, { text: `Aceitação do crivo.`, id: `B`, isCorrect: false }, { text: `Tratamento do risco.`, id: `C`, isCorrect: false }, { text: `Monitoramento e análise crítica de riscos.`, id: `D`, isCorrect: true }, { text: `Marcação do critério.`, id: `E`, isCorrect: false } ],
            gabaritoComentado: `Riscos residuais exigem monitoramento e análise crítica contínuos.`
        }
    ];

    const randomizableQuestionPool = [
        { qIdPrefix: `rand_`, stableId: `RAND_CF_CID_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: simulados.pdf, p. 13, Q9]`, text: `A tríade CID é uma forma simplificada de representar os múltiplos objetivos da segurança da informação. O que a triade CID, que o SGSI busca preservar, representa?`, options: [ { text: `Complacência, Integridade, Durabilidade.`, id: `A`, isCorrect: false }, { text: `Confidencialidade, Integridade, Disponibilidade.`, id: `B`, isCorrect: true }, { text: `Consistência, Implementação, Durabilidade.`, id: `C`, isCorrect: false }, { text: `Computação, Internet, Dados.`, id: `D`, isCorrect: false }, { text: `Certificação, Inovação, Desenvolvimento.`, id: `E`, isCorrect: false } ], gabaritoComentado: `CID: Confidencialidade, Integridade e Disponibilidade.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_VULNERABILIDADE_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: Prova AV.pdf, p. 1, Q2 / simulados.pdf, p.4, Q6]`, text: `Na segurança da informação, a fragilidade de um ativo ou grupo de ativos, que pode ser explorada por uma ou mais ameaças, é chamada de:`, options: [ { text: `Risco.`, id: `A`, isCorrect: false }, { text: `Incidente de segurança da informação.`, id: `B`, isCorrect: false }, { text: `Ameaça.`, id: `C`, isCorrect: false }, { text: `Vulnerabilidade.`, id: `D`, isCorrect: true }, { text: `Desastre.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Vulnerabilidade é a fragilidade de um ativo que pode ser explorada por ameaças.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_CONFIDENCIALIDADE_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: PRATICANDO.pdf, p. 8, Desafio 1 / simulados.pdf, p.3, Q5]`, text: `Qual característica da segurança da informação você deve priorizar para garantir que informações confidenciais sejam acessadas apenas por quem tem autorização?`, options: [ { text: `Disponibilidade.`, id: `A`, isCorrect: false }, { text: `Integridade.`, id: `B`, isCorrect: false }, { text: `Não Repúdio.`, id: `C`, isCorrect: false }, { text: `Autenticidade.`, id: `D`, isCorrect: false }, { text: `Confidencialidade.`, id: `E`, isCorrect: true } ], gabaritoComentado: `A confidencialidade é o princípio que assegura que a informação seja acessada apenas por pessoas autorizadas.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_AUTENTICIDADE_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: PRATICANDO.pdf, p. 11, Desafio 3]`, text: `Considerando a necessidade de verificar se os sistemas garantem que todas as informações são manipuladas por pessoas ou sistemas que possam ser confirmados como legítimos, o que é garantido pelo princípio da autenticidade na segurança da informação?`, options: [ { text: `Garante que apenas pessoas autorizadas terão acesso à informação.`, id: `A`, isCorrect: false }, { text: `Garante um tratamento igual entre todas as pessoas.`, id: `B`, isCorrect: false }, { text: `Garante que apenas pessoas autorizadas poderão alterar a informação.`, id: `C`, isCorrect: false }, { text: `Garante que a informação estará disponível sempre que um usuário autorizado quiser acessá-la.`, id: `D`, isCorrect: false }, { text: `Garante a veracidade da autoria da informação, além do não repúdio.`, id: `E`, isCorrect: true } ], gabaritoComentado: `O princípio da autenticidade assegura que as informações sejam genuínas e que a autoria ou fonte possa ser verificada e confirmada, incluindo o não repúdio.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_VULN_ENTRE_AMEACAS_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: Prova AV.pdf, p. 2, Q3]`, text: `(CESGRANRIO/2014) Durante um processo de identificação de ameaças e vulnerabilidades, um analista deveria gerar uma lista de ameaças, mas cometeu um engano e incluiu entre elas uma vulnerabilidade. Qual é a vulnerabilidade listada entre as ameaças?`, options: [ { text: `Hacker.`, id: `A`, isCorrect: false }, { text: `Vírus.`, id: `B`, isCorrect: false }, { text: `Porta TCP aberta.`, id: `C`, isCorrect: true }, { text: `Funcionário descontente.`, id: `D`, isCorrect: false }, { text: `Instabilidade de energia.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Porta TCP aberta é uma fragilidade (vulnerabilidade) que pode ser explorada. As outras opções são ameaças (agentes ou eventos).` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_AUTENTICACAO_DEF_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: simulados.pdf, p. 8, Q1]`, text: `O crescimento das redes abertas (...) surgiu a necessidade de verificação da identidade tanto dos usuários quanto dos sistemas e processos. Dentro desse contexto, esse ato de verificação é chamado:`, options: [ { text: `Configuração.`, id: `A`, isCorrect: false }, { text: `Acessibilidade.`, id: `B`, isCorrect: false }, { text: `Autenticação.`, id: `C`, isCorrect: true }, { text: `Confiabilidade.`, id: `D`, isCorrect: false }, { text: `Cadastro.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Autenticação é o processo de verificar a identidade de um usuário, sistema ou processo.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_CONFIDENCIALIDADE_LAPTOPS_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: simulados.pdf, p. 8, Q2]`, text: `Qual problema de segurança é destacado nos exemplos de laptops levados para manutenção e discos rígidos de segunda mão comprados na Internet, como por exemplo, no eBay?`, options: [ { text: `Falha na integridade dos dados.`, id: `A`, isCorrect: false }, { text: `Problemas na disponibilidade da informação.`, id: `B`, isCorrect: false }, { text: `Falhas na confidencialidade dos dados.`, id: `C`, isCorrect: true }, { text: `Ausência de autenticidade dos dados.`, id: `D`, isCorrect: false }, { text: `Violações de não repúdio.`, id: `E`, isCorrect: false } ], gabaritoComentado: `A exposição de dados em laptops ou discos rígidos descartados/vendidos representa uma falha na confidencialidade.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_CONCEITOS_AMEACA_RISCO_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: simulados.pdf, p. 11, Q6]`, text: `Sobre os conceitos de segurança da informação, analise as afirmativas a seguir:<br>I. Uma ameaça tem o poder de comprometer ativos vulneráveis.<br>II. Risco é a combinação das consequências de um incidente de segurança com a sua probabilidade de ocorrência.<br>III. Vulnerabilidades técnicas são mais críticas do que vulnerabilidades criadas por comportamento humano.<br>Está correto somente o que se afirma em:`, options: [ { text: `I`, id: `A`, isCorrect: false }, { text: `II`, id: `B`, isCorrect: false }, { text: `III`, id: `C`, isCorrect: false }, { text: `I e II`, id: `D`, isCorrect: true }, { text: `I e III`, id: `E`, isCorrect: false } ], gabaritoComentado: `I e II estão corretas. III é incorreta pois vulnerabilidades humanas são frequentemente consideradas muito críticas.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_ATIVO_LOGICO_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: simulados.pdf, p. 12, Q7]`, text: `De maneira geral, qual exemplo pode ser considerado um ativo lógico? (Considerando o contexto de SI, onde 'lógico' se opõe a 'físico')`, options: [ { text: `Informação.`, id: `A`, isCorrect: true }, { text: `Servidor (Hardware).`, id: `B`, isCorrect: false }, { text: `Colaboradores.`, id: `C`, isCorrect: false }, { text: `Edifício.`, id: `D`, isCorrect: false }, { text: `Imagem da organização.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Informação é um ativo lógico primário em Segurança da Informação. Hardware é físico. Imagem e Colaboradores são outros tipos de ativos.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CF_RISCO_AMEACA_VULN_CONTEXTO_01`, topicKey: 'CONCEITOS_FUNDAMENTAIS', sourceRef: `[Fonte: PRATICANDO.pdf, p.3 Estudo de Caso]`, text: `No estudo de caso da TechSecure, hackers exploraram 'vulnerabilidades no sistema de gerenciamento de senhas e nos controles de acesso'. A tentativa de invasão em si representa uma:`, options: [ { text: `Vulnerabilidade`, id: `A`, isCorrect: false }, { text: `Ameaça (concretizada)`, id: `B`, isCorrect: true }, { text: `Controle`, id: `C`, isCorrect: false }, { text: `Ativo`, id: `D`, isCorrect: false }, { text: `Risco (materializado)`, id: `E`, isCorrect: false } ], gabaritoComentado: `A tentativa de invasão é a ação da ameaça (hackers). A vulnerabilidade é a falha que permitiu. O risco é a combinação da probabilidade dessa ameaça explorar a vulnerabilidade e o impacto resultante.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CS_FIREWALL_POL_01`, topicKey: 'CONTROLES_SEGURANCA', sourceRef: `[Fonte: PRATICANDO.pdf, p. 5, Desafio 2]`, text: `Considerando as melhores práticas de segurança, qual é a politica mais comumente recomendada para configurar as regras de firewall e garantir que a rede esteja adequadamente protegida contra acessos não autorizados?`, options: [ { text: `Aceitar todos por padrão, negar alguns.`, id: `A`, isCorrect: false }, { text: `Negar por padrão, autorizar explicitamente.`, id: `B`, isCorrect: true }, { text: `Aceitar por padrão, negar por exceção.`, id: `C`, isCorrect: false }, { text: `Autorizar todos por padrão, restringir alguns.`, id: `D`, isCorrect: false }, { text: `Negar todos por padrão, sem exceções.`, id: `E`, isCorrect: false } ], gabaritoComentado: `A prática mais recomendada é configurar o firewall para negar todo o tráfego por padrão e autorizar explicitamente apenas o que é necessário (deny by default).` },
        { qIdPrefix: `rand_`, stableId: `RAND_CS_HASH_01`, topicKey: 'CONTROLES_SEGURANCA', sourceRef: `[Fonte: simulados.pdf, p. 2, Q3]`, text: `Complete a frase corretamente: "as funções de hash, por exemplo, são adequadas para garantir a integridade dos dados, porque ..."`, options: [ { text: `Qualquer alteração feita no conteúdo de uma mensagem fará com que o receptor calcule um valor de hash diferente daquele colocado na transmissão pelo remetente.`, id: `A`, isCorrect: true }, { text: `Geralmente podem ser calculadas muito mais rápido que os valores de criptografia de chave pública.`, id: `B`, isCorrect: false }, { text: `Usam chave única para criptografar e descriptografar a mensagem.`, id: `C`, isCorrect: false }, { text: `Fazem a troca de chaves na chave simétrica.`, id: `D`, isCorrect: false }, { text: `Utilizam algoritmos de criptografia de chave pública.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Funções de hash garantem a integridade, pois qualquer alteração na mensagem original resulta em um hash diferente.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CS_SEGURANCAFISICA_01`, topicKey: 'CONTROLES_SEGURANCA', sourceRef: `[Fonte: PRATICANDO.pdf, p. 4, Desafio 1]`, text: `Com base nas melhores práticas de segurança, qual das seguintes opções seria mais adequada para ser utilizada como a primeira linha de defesa ao se aproximar das instalações da empresa?`, options: [ { text: `Firewalls.`, id: `A`, isCorrect: false }, { text: `Criptografia.`, id: `B`, isCorrect: false }, { text: `Catraças e elevadores.`, id: `C`, isCorrect: false }, { text: `Cancelas com seguranças verificando identificações.`, id: `D`, isCorrect: true }, { text: `Sistemas de detecção de intrusão.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Cancelas com seguranças verificando identificações representam a primeira linha de defesa física ao se aproximar de uma instalação.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CS_ANTIVIRUS_01`, topicKey: 'CONTROLES_SEGURANCA', sourceRef: `[Fonte: simulados.pdf, p. 3, Q4]`, text: `(AMEOSC/2022 Adaptada) Protege o computador contra outros programas potencialmente danosos. Ele detecta, impede e atua na remoção de programas maliciosos, como vírus e worms. Marque a alternativa CORRETA que corresponde ao contexto acima.`, options: [ { text: `Proxy.`, id: `A`, isCorrect: false }, { text: `Antivírus.`, id: `B`, isCorrect: true }, { text: `Firewall.`, id: `C`, isCorrect: false }, { text: `Painel de Controle.`, id: `D`, isCorrect: false }, { text: `Roteador.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Antivírus é o software que detecta, impede e remove programas maliciosos.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CS_CRYPTO_CHAVES_01`, topicKey: 'CONTROLES_SEGURANCA', sourceRef: `[Fonte: PRATICANDO.pdf, p. 6-7, Desafio 3]`, text: `Considerando $R^+$ e $R^-$ as chaves pública e privada do remetente, e $D^+$ e $D^-$ as chaves pública e privada do destinatário, para garantir a confidencialidade de uma mensagem, o remetente deve usar ______ para criptografar, e o destinatário usará ______ para decriptar.`, options: [ { text: `$R^+$, $R^-$`, id: `A`, isCorrect: false }, { text: `$D^+$, $D^-$`, id: `B`, isCorrect: true }, { text: `$R^-$, $R^+$`, id: `C`, isCorrect: false }, { text: `$D^-$, $D^+$`, id: `D`, isCorrect: false }, { text: `$R^+$, $D^-$`, id: `E`, isCorrect: false } ], gabaritoComentado: `Para confidencialidade, a mensagem é criptografada com a chave pública do destinatário ($D^+$) e decriptada com a chave privada do destinatário ($D^-$).` },
        { qIdPrefix: `rand_`, stableId: `RAND_CS_BACKUP_IMPORTANCE_01`, topicKey: 'CONTROLES_SEGURANCA', sourceRef: `[Fonte: PRATICANDO.pdf, p. 18, Desafio 2 / simulados.pdf, p.1, Q1]`, text: `Qual das opções a seguir melhor justifica a necessidade de backups regulares como medida de segurança?`, options: [ { text: `Backup é um desperdício de tempo e recursos...`, id: `A`, isCorrect: false }, { text: `Realizar backups permite que você se livre de dados antigos...`, id: `B`, isCorrect: false }, { text: `Caso as informações sejam perdidas ou corrompidas..., um backup recente pode ser restaurado, garantindo a continuidade das operações.`, id: `C`, isCorrect: true }, { text: `Os backups são importantes apenas para grandes empresas...`, id: `D`, isCorrect: false }, { text: `Os backups são úteis apenas para fins de auditoria...`, id: `E`, isCorrect: false } ], gabaritoComentado: `Backups regulares são essenciais para restaurar dados em caso de falhas, malware ou erros humanos, garantindo a continuidade das operações.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CS_PROTECAO_EQUIPAMENTO_01`, topicKey: 'CONTROLES_SEGURANCA', sourceRef: `[Fonte: Prova AV.pdf, p. 2, Q4]`, text: `Um funcionário esbarrou em um servidor web que estava no canto de uma mesa e o derrubou, parando a operação do mesmo. Segundo a norma ABNT NBR ISO/IEC 27002:2013, o responsável pela segurança do servidor deixou de colocar em prática o controle relacionado à:`, options: [ { text: `Segregação de funções.`, id: `A`, isCorrect: false }, { text: `Inventário dos ativos.`, id: `B`, isCorrect: false }, { text: `Acordo de confidencialidade.`, id: `C`, isCorrect: false }, { text: `Localização e proteção do equipamento.`, id: `D`, isCorrect: true }, { text: `Gerenciamento de senha de usuário.`, id: `E`, isCorrect: false } ], gabaritoComentado: `A norma ISO/IEC 27002 aborda a importância da localização e proteção física dos equipamentos para prevenir danos, acessos não autorizados ou interrupções.` },
        { qIdPrefix: `rand_`, stableId: `RAND_CS_BOAS_PRATICAS_SENHA_01`, topicKey: 'CONTROLES_SEGURANCA', sourceRef: `[Fonte: simulados.pdf, p. 2, Q2]`, text: `Qual das opções abaixo é considerada uma boa prática de segurança referente a senhas?`, options: [ { text: `Nunca compartilhar senhas.`, id: `A`, isCorrect: true }, { text: `Usar a mesma senha para múltiplos serviços para facilitar a memorização.`, id: `B`, isCorrect: false }, { text: `Anotar senhas em post-its colados no monitor.`, id: `C`, isCorrect: false }, { text: `Escolher senhas curtas e fáceis de adivinhar, como "123456".`, id: `D`, isCorrect: false }, { text: `Desabilitar a autenticação multifator sempre que possível.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Nunca compartilhar senhas é uma boa prática fundamental de segurança da informação. As outras opções representam práticas inseguras.` },
        { qIdPrefix: `rand_`, stableId: `RAND_AE_MALWARE_BOTS_01`, topicKey: 'AMEACAS_ESPECIFICAS', sourceRef: `[Fonte: ATIVIDADES PDF, p. 1, Q2]`, text: `(FCC/2012- Adaptada) Códigos maliciosos (malwares) são programas desenvolvidos para executar ações danosas. Sobre bots e botnets, é correto afirmar:`, options: [ { text: `Botnet é um software malicioso de monitoramento individual de teclado.`, id: `A`, isCorrect: false }, { text: `Bot é um programa que depende da ação do usuário para se replicar.`, id: `B`, isCorrect: false }, { text: `Um computador infectado por um bot é chamado de 'servidor mestre'.`, id: `C`, isCorrect: false }, { text: `A comunicação entre o invasor e o computador infectado (zumbi) ocorre exclusivamente via HTTP.`, id: `D`, isCorrect: false }, { text: `Algumas das ações maliciosas executadas por botnets são: ataques de negação de serviço (DoS/DDoS), envio de spam e furto de dados.`, id: `E`, isCorrect: true } ], gabaritoComentado: `Botnets são redes de computadores infectados (zumbis) controlados por um invasor para realizar ataques em massa, como DoS/DDoS.` },
        { qIdPrefix: `rand_`, stableId: `RAND_AE_RANSOMWARE_01`, topicKey: 'AMEACAS_ESPECIFICAS', sourceRef: `[Fonte: ATIVIDADES PDF, p. 2, Q3]`, text: `É um tipo de malware feito para extorquir dinheiro da vítima, geralmente criptografando seus arquivos e exigindo um resgate para liberá-los. O texto se refere ao:`, options: [ { text: `Spyware`, id: `A`, isCorrect: false },{ text: `Botnet`, id: `B`, isCorrect: false }, { text: `Spam`, id: `C`, isCorrect: false },{ text: `DDOS`, id: `D`, isCorrect: false }, { text: `Ransomware`, id: `E`, isCorrect: true } ], gabaritoComentado: `O enunciado descreve o Ransomware, que sequestra dados e exige resgate.` },
        { qIdPrefix: `rand_`, stableId: `RAND_AE_ENGSOCIAL_RISCO_01`, topicKey: 'AMEACAS_ESPECIFICAS', sourceRef: `[Fonte: PRATICANDO.pdf, p. 9, Desafio 2]`, text: `Considerando o contexto de fraudes digitais que exploram falhas humanas, qual é o principal risco associado ao uso de técnicas de engenharia social?`, options: [ { text: `Códigos maliciosos nos computadores.`, id: `A`, isCorrect: false }, { text: `Criptoanálises de senhas.`, id: `B`, isCorrect: false }, { text: `Boatos espalhados pela internet.`, id: `C`, isCorrect: false }, { text: `Fraudes contra os usuários.`, id: `D`, isCorrect: true }, { text: `Quebras de privacidade dos usuários.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Engenharia social é amplamente utilizada para enganar e manipular usuários, levando-os a realizar ações que resultam em fraudes.` },
        { qIdPrefix: `rand_`, stableId: `RAND_AE_VIRUS_BLINDADO_01`, topicKey: 'AMEACAS_ESPECIFICAS', sourceRef: `[Fonte: PRATICANDO.pdf, p. 17, Desafio 1 / Prova AV.pdf, p.6, Q9]`, text: `Um vírus estava tentando evitar a detecção, fazendo com que o antivírus acreditasse que o programa malicioso estava em uma localização diferente da real. Qual tipo de vírus possui essa habilidade?`, options: [ { text: `Vírus blindado.`, id: `A`, isCorrect: true }, { text: `Vírus stealth.`, id: `B`, isCorrect: false }, { text: `Polimórfico.`, id: `C`, isCorrect: false }, { text: `Mutante.`, id: `D`, isCorrect: false }, { text: `Cavalo de Troia.`, id: `E`, isCorrect: false } ], gabaritoComentado: `O vírus blindado é projetado para dificultar a análise, enganando o antivírus sobre sua localização real.` },
        { qIdPrefix: `rand_`, stableId: `RAND_AE_PHISHING_DEFINE_01`, topicKey: 'AMEACAS_ESPECIFICAS', sourceRef: `[Fonte: PRATICANDO.pdf, p. 20, Desafio 3]`, text: `Qual das alternativas abaixo define corretamente o phishing?`, options: [ { text: `É o termo usado para se referir aos e-mails não solicitados...`, id: `A`, isCorrect: false }, { text: `São programas especificamente desenvolvidos para executar ações danosas...`, id: `B`, isCorrect: false }, { text: `É um software projetado para monitorar as atividades de um sistema...`, id: `C`, isCorrect: false }, { text: `São programas, ou parte de um programa de computador, normalmente maliciosos...`, id: `D`, isCorrect: false }, { text: `É um método de envio de mensagens eletrônicas que tentam se passar pela comunicação oficial de uma instituição conhecida...`, id: `E`, isCorrect: true } ], gabaritoComentado: `Phishing é um método de envio de mensagens eletrônicas fraudulentas que se passam por comunicações oficiais para roubar informações sensíveis.` },
        { qIdPrefix: `rand_`, stableId: `RAND_NS_ISO27001_OBJ_01`, topicKey: 'NORMAS_SEGURANCA', sourceRef: `[Fonte: Prova AV.pdf, p. 5, Q7 / PRATICANDO.pdf, p.12, Desafio 1]`, text: `Qual norma técnica possui o seguinte título: "Tecnologia da informação - Técnicas de segurança - Sistemas de gestão da segurança da informação - Requisitos"?`, options: [ { text: `ABNT NBR ISO/IEC 27001:2013`, id: `A`, isCorrect: true }, { text: `ABNT NBR ISO/IEC 27002:2013`, id: `B`, isCorrect: false }, { text: `ABNT NBR ISO/IEC 20000-1:2011`, id: `C`, isCorrect: false }, { text: `ABNT NBR ISO 9001:2008`, id: `D`, isCorrect: false }, { text: `ABNT NBR ISO 14001:2004`, id: `E`, isCorrect: false } ], gabaritoComentado: `A norma ABNT NBR ISO/IEC 27001:2013 estabelece os requisitos para um Sistema de Gestão de Segurança da Informação (SGSI).` },
        { qIdPrefix: `rand_`, stableId: `RAND_NS_ISO27001_BENEFIT_01`, topicKey: 'NORMAS_SEGURANCA', sourceRef: `[Fonte: PRATICANDO.pdf, p. 14, Desafio 2]`, text: `Qual das opções abaixo representa um dos principais benefícios da adoção da norma ISO/IEC 27001:2013?`, options: [ { text: `Oportunidade de identificar e eliminar fraquezas`, id: `A`, isCorrect: true }, { text: `Mecanismo para eliminar o sucesso do sistema`, id: `B`, isCorrect: false }, { text: `Não participação da gerência na segurança da informação`, id: `C`, isCorrect: false }, { text: `Fornece insegurança a todas as partes interessadas`, id: `D`, isCorrect: false }, { text: `Isola recursos com outros sistemas de gerenciamento`, id: `E`, isCorrect: false } ], gabaritoComentado: `A adoção da ISO/IEC 27001:2013 permite que uma organização identifique fraquezas e vulnerabilidades, sendo fundamental para melhorias contínuas.` },
        { qIdPrefix: `rand_`, stableId: `RAND_NS_ISO_SURVEY_01`, topicKey: 'NORMAS_SEGURANCA', sourceRef: `[Fonte: PRATICANDO.pdf, p. 15, Desafio 3 / simulados.pdf, p.12, Q8]`, text: `Qual das opções abaixo melhor define o "The ISO Survey of Certifications"?`, options: [ { text: `Um site onde as organizações podem obter certificações ISO`, id: `A`, isCorrect: false }, { text: `Uma revista anual sobre as atualizações das normas ISO`, id: `B`, isCorrect: false }, { text: `Uma pesquisa anual sobre o número de certificados válidos para os padrões do sistema de gerenciamento ISO em todo o mundo`, id: `C`, isCorrect: true }, { text: `Uma conferência onde são discutidos os padrões ISO`, id: `D`, isCorrect: false }, { text: `Uma organização que define as normas ISO`, id: `E`, isCorrect: false } ], gabaritoComentado: `O "The ISO Survey of Certifications" é uma pesquisa anual da ISO que coleta dados sobre o número de certificados válidos emitidos para as normas de sistemas de gestão ISO.` },
        { qIdPrefix: `rand_`, stableId: `RAND_NS_PROCEDIMENTO_SEGURANCA_ORG_01`, topicKey: 'NORMAS_SEGURANCA', sourceRef: `[Fonte: simulados.pdf, p. 9-10, Q4]`, text: `Assinale a alternativa que apresenta procedimento de segurança da informação que pode ser adotado pelas organizações, alinhado com boas práticas e normativas.`, options: [ { text: `Realizar, periodicamente, análises de riscos, com o objetivo de contemplar as mudanças nos requisitos de segurança da informação`, id: `A`, isCorrect: true }, { text: `Não envolver a direção com a segurança da informação, delegando totalmente a responsabilidade ao TI.`, id: `B`, isCorrect: false }, { text: `Descartar o inventário dos ativos para simplificar a gestão.`, id: `C`, isCorrect: false }, { text: `Evitar treinamentos em segurança da informação para não alarmar os funcionários.`, id: `D`, isCorrect: false }, { text: `Conceder aos funcionários o acesso completo a todos os sistemas e à rede (intranet) da organização para maior agilidade.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Realizar análises de riscos periodicamente é um procedimento fundamental de segurança da informação, preconizado por normas como a ISO 27001.` },
        { qIdPrefix: `rand_`, stableId: `RAND_NS_ISO27001_NAO_BENEFICIO_01`, topicKey: 'NORMAS_SEGURANCA', sourceRef: `[Fonte: simulados.pdf, p. 13, Q10]`, text: `Assinale a assertiva que NÃO representa um dos benefícios para a adoção da norma ABNT NBR ISO/IEC 27001:2013 por uma organização:`, options: [ { text: `Oportunidade de identificar e eliminar fraquezas`, id: `A`, isCorrect: false }, { text: `Mecanismo para minimizar o fracasso do sistema de gestão de segurança`, id: `B`, isCorrect: false }, { text: `Participação e comprometimento da gerência na Segurança da Informação`, id: `C`, isCorrect: false }, { text: `Fornece segurança e confiança a todas as partes interessadas`, id: `D`, isCorrect: false }, { text: `Isola recursos de segurança com outros sistemas de gerenciamento da organização`, id: `E`, isCorrect: true } ], gabaritoComentado: `A ISO 27001 é projetada para ser integrada com outros sistemas de gestão (como ISO 9001, etc.), não para isolar recursos. As outras opções são benefícios ou aspectos positivos.` },
        { qIdPrefix: `rand_`, stableId: `RAND_NS_ESTUDO_CASO_ISO_01`, topicKey: 'NORMAS_CRITICAS', highlight: true, sourceRef: `[Fonte: PRATICANDO.pdf, p.3 Estudo de Caso]`, text: `No caso da TechSecure, que adota parcialmente as normas ISO/IEC 27001 e 27002, qual a principal recomendação para corrigir as vulnerabilidades e garantir a conformidade total?`, options: [ { text: `Aumentar apenas o investimento em antivírus.`, id: `A`, isCorrect: false }, { text: `Realizar uma auditoria completa dos sistemas de segurança para identificar e corrigir lacunas na implementação das normas ISO...`, id: `B`, isCorrect: true }, { text: `Demitir a equipe de TI do fim de semana.`, id: `C`, isCorrect: false }, { text: `Migrar todos os dados para a nuvem sem uma análise prévia.`, id: `D`, isCorrect: false }, { text: `Ignorar as normas ISO e focar apenas em firewalls.`, id: `E`, isCorrect: false } ], gabaritoComentado: `A chave de resposta indica a necessidade de uma auditoria completa das normas ISO.` },
        { qIdPrefix: `rand_`, stableId: `RAND_GR_AVALIACAO_RISCOS_01`, topicKey: 'GESTAO_RISCO', sourceRef: `[Fonte: simulados.pdf, p. 5, Q7]`, text: `Um funcionário... concluiu que existe uma probabilidade de 67% de sobrecarga... Dentro da Gestão de Riscos (GR), essa conclusão pode ser obtida na etapa de:`, options: [ { text: `Definição do contexto.`, id: `A`, isCorrect: false }, { text: `Monitoramento e controle de riscos.`, id: `B`, isCorrect: false }, { text: `Processo de avaliação de riscos (Análise de Riscos).`, id: `C`, isCorrect: true }, { text: `Tratamento de riscos.`, id: `D`, isCorrect: false }, { text: `Aceitação do risco (residual).`, id: `E`, isCorrect: false } ], gabaritoComentado: `A identificação da probabilidade e impacto faz parte da avaliação/análise de riscos.` },
        { qIdPrefix: `rand_`, stableId: `RAND_GR_RISCO_DEFINICAO_01`, topicKey: 'GESTAO_RISCO', sourceRef: `[Fonte: simulados.pdf, p. 6, Q10]`, text: `A respeito do conceito de Risco em Segurança da Informação, selecione a opção correta:`, options: [ { text: `É o efeito da incerteza nos objetivos, podendo ser positivo ou negativo.`, id: `A`, isCorrect: true }, { text: `Um evento súbito e imprevisto que provoca grandes perdas...`, id: `B`, isCorrect: false }, { text: `Algo que sempre pode ser totalmente eliminado...`, id: `C`, isCorrect: false }, { text: `Refere-se exclusivamente a ameaças externas...`, id: `D`, isCorrect: false }, { text: `É um sinônimo direto de vulnerabilidade.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Risco é o efeito da incerteza nos objetivos.` },
        { qIdPrefix: `rand_`, stableId: `RAND_GR_LINK_INSTAVEL_SLA_01`, topicKey: 'GESTAO_RISCO', sourceRef: `[Fonte: simulados.pdf, p. 10, Q5]`, text: `O link de acesso à internet de uma instituição encontra-se muito instável porque o seu provedor não cumpre o SLA... Do ponto de vista de segurança e análise de risco, isso deve ser considerado como evidência de:`, options: [ { text: `BYOD.`, id: `A`, isCorrect: false }, { text: `Ameaça.`, id: `B`, isCorrect: false }, { text: `Negação de serviço.`, id: `C`, isCorrect: false }, { text: `Vulnerabilidade.`, id: `D`, isCorrect: true }, { text: `Incidente.`, id: `E`, isCorrect: false } ], gabaritoComentado: `A dependência de um provedor instável é uma vulnerabilidade.` },
        { qIdPrefix: `rand_`, stableId: `RAND_GR_RISCOS_RESIDUAIS_01`, topicKey: 'GESTAO_RISCO', sourceRef: `[Fonte: PRATICANDO.pdf, p. 23, Desafio 2]`, text: `O que são riscos residuais na gestão de riscos de segurança da informação?`, options: [ { text: `Riscos que não podem ser tratados.`, id: `A`, isCorrect: false }, { text: `Riscos que foram aceitos pela organização.`, id: `B`, isCorrect: true }, { text: `Riscos que foram totalmente eliminados.`, id: `C`, isCorrect: false }, { text: `Riscos que não foram identificados.`, id: `D`, isCorrect: false }, { text: `Riscos que foram transferidos para terceiros.`, id: `E`, isCorrect: false } ], gabaritoComentado: `Riscos residuais são aqueles que permanecem após o tratamento e são aceitos.` },
        { qIdPrefix: `rand_`, stableId: `RAND_GCN_PGCN_OBJETIVO_01`, topicKey: 'GESTAO_CONTINUIDADE', sourceRef: `[Fonte: PRATICANDO.pdf, p. 27, Desafio 2 / simulados.pdf, p.5, Q8]`, text: `Com base na norma NBR15999-1 (2007), qual é o principal objetivo da Política de Gestão de Continuidade de Negócios (PGCN)?`, options: [ { text: `Melhorar a eficiência dos processos...`, id: `A`, isCorrect: false }, { text: `Atender a regulamentações de segurança cibernética.`, id: `B`, isCorrect: false }, { text: `Fornecer uma base para entender, desenvolver e implementar a continuidade de negócios...`, id: `C`, isCorrect: true },  { text: `Implementar práticas de gerenciamento de projetos.`, id: `D`, isCorrect: false }, { text: `Criar planos de marketing para a organização.`, id: `E`, isCorrect: false } ], gabaritoComentado: `PGCN visa fornecer base para entender, desenvolver e implementar a continuidade de negócios.` },
        { qIdPrefix: `rand_`, stableId: `RAND_GCN_PDCA_MELHORIA_01`, topicKey: 'GESTAO_CONTINUIDADE', sourceRef: `[Fonte: PRATICANDO.pdf, p. 26, Desafio 1]`, text: `No contexto do ciclo PDCA (Planejar, Fazer, Checar, Agir) utilizado para um Plano de Continuidade de Negócios (PCN), qual das etapas é responsável por promover a melhoria contínua do plano?`, options: [ { text: `P - Planejar.`, id: `A`, isCorrect: false }, { text: `D- Executar.`, id: `B`, isCorrect: false }, { text: `C - Checar.`, id: `C`, isCorrect: false }, { text: `A - Agir.`, id: `D`, isCorrect: true }, { text: `O PDCA não é adequado para o PCN.`, id: `E`, isCorrect: false } ], gabaritoComentado: `A fase "Agir" (Act) do PDCA é responsável pela melhoria contínua.` },
        { qIdPrefix: `rand_`, stableId: `RAND_GCN_PCN_INSTRUMENTO_PDCA_01`, topicKey: 'GESTAO_CONTINUIDADE', sourceRef: `[Fonte: simulados.pdf, p. 6, Q9 / PRATICANDO.pdf, p.29, Desafio 3]`, text: `Marque a alternativa que indica o instrumento/metodologia mais utilizado para a implementação e melhoria contínua do PCN (Planejamento de Continuidade de Negócios).`, options: [ { text: `SWOT`, id: `A`, isCorrect: false }, { text: `BSC`, id: `B`, isCorrect: false }, { text: `PDCA`, id: `C`, isCorrect: true }, { text: `ROI`, id: `D`, isCorrect: false }, { text: `CRM`, id: `E`, isCorrect: false } ], gabaritoComentado: `O PDCA é amplamente utilizado para implementação e melhoria de PCN.` },
        { qIdPrefix: `rand_`, stableId: `RAND_GCN_AV_PCN_PDCA_ETAPA_IMPL_01`, topicKey: 'GESTAO_CONTINUIDADE', sourceRef: `[Fonte: Prova AV.pdf, p. 7, Q10]`, text: `Em relação ao ciclo básico de atividades recomendado pela NBR 15999 para a realização de um bom Plano de Continuidade de Negócios (PCN)...selecione a etapa na qual serão implementadas as estratégias...:`, options: [ { text: `Mapeamento de Negócios.`, id: `A`, isCorrect: false }, { text: `Análise de Impacto de Negócios.`, id: `B`, isCorrect: false }, { text: `Definição de Melhores Estratégias.`, id: `C`, isCorrect: false }, { text: `Desenvolvimento e Implementação da Resposta de GCN (Fazer/Executar).`, id: `D`, isCorrect: true }, { text: `Testes e Simulações.`, id: `E`, isCorrect: false } ], gabaritoComentado: `A implementação das estratégias ocorre na fase "Fazer" (Do) ou "Desenvolvimento e Implementação da Resposta de GCN".` }
    ];

    let currentQuizQuestions = [];
    const questionsState = [];
    const questionsArea = document.getElementById('questions-area-main');
    const navGrid = document.getElementById('question-nav-grid');
    const finalizeButton = document.getElementById('finalize-button');
    const restartButton = document.getElementById('restart-button');
    const themeToggleButton = document.getElementById('theme-toggle-button');
    const answeredCountEl = document.getElementById('answered-count');
    const reviewCountEl = document.getElementById('review-count');
    const blankCountEl = document.getElementById('blank-count');

    const modeSelectionScreen = document.getElementById('mode-selection-screen');
    const quizMainContainer = document.getElementById('quiz-main-container');
    const startTimedButton = document.getElementById('start-timed-button');
    const startUntimedButton = document.getElementById('start-untimed-button');
    const quizHeaderBackButton = document.getElementById('back-button');
    const probabilityLegendContainer = document.getElementById('probability-legend-container');
    const probabilityLegendTitle = probabilityLegendContainer.querySelector('p:first-child');


    const timerDisplayContainer = document.getElementById('timer-display-container');
    const timerDisplay = document.getElementById('timer-display');

    let quizFinalized = false;
    let isTimedModeGlobal = false;
    let timerIntervalGlobal = null;
    let remainingSecondsGlobal = 0;
    const QUIZ_DURATION_SECONDS = 50 * 60;

    function shuffleArray(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
    }

    function buildCurrentQuiz() {
        currentQuizQuestions = [];

        let poolForSelection;
        if (isTimedModeGlobal) {
            poolForSelection = [...JSON.parse(JSON.stringify(baseFixedQuestions)), ...JSON.parse(JSON.stringify(randomizableQuestionPool))];
            shuffleArray(poolForSelection);
            currentQuizQuestions = poolForSelection.slice(0, 10);
            currentQuizQuestions.forEach((q, index) => {
                q.qNumberDisplay = (index + 1).toString();
                q.qId = `timed_q${index + 1}_${Date.now()}_${Math.random().toString(36).substring(7)}`;
            });
        } else {
            currentQuizQuestions = new Array(10).fill(null);
            const localBaseFixedQuestions = JSON.parse(JSON.stringify(baseFixedQuestions));
            const fixedMappingUntimed = [
                { quizSlot: 0, baseFixedIndex: 0, displayNumber: '1' },
                { quizSlot: 4, baseFixedIndex: 1, displayNumber: '5' },
                { quizSlot: 5, baseFixedIndex: 2, displayNumber: '6' },
                { quizSlot: 6, baseFixedIndex: 3, displayNumber: '7' },
                { quizSlot: 7, baseFixedIndex: 4, displayNumber: '8' }
            ];

            fixedMappingUntimed.forEach(map => {
                if (localBaseFixedQuestions[map.baseFixedIndex]) {
                    const questionData = localBaseFixedQuestions[map.baseFixedIndex];
                    questionData.qId = `${questionData.qIdPrefix || 'bfq_'}_slot${map.quizSlot}_${Date.now()}_${Math.random().toString(36).substring(7)}`;
                    questionData.qNumberDisplay = map.displayNumber;
                    currentQuizQuestions[map.quizSlot] = questionData;
                }
            });

            let availableRandomQuestions = JSON.parse(JSON.stringify(randomizableQuestionPool)).filter(
                rq => !currentQuizQuestions.some(cq => cq && cq.stableId === rq.stableId)
            );
            shuffleArray(availableRandomQuestions);

            let randomPoolIdx = 0;
            const randomDisplayNumbersUntimed = ['2', '3', '4', '9', '10'];
            const randomSlotsUntimed = [1, 2, 3, 8, 9];

            randomSlotsUntimed.forEach((slotIndex, k) => {
                if (currentQuizQuestions[slotIndex] === null) {
                    if (randomPoolIdx < availableRandomQuestions.length) {
                        const questionData = availableRandomQuestions[randomPoolIdx++];
                        questionData.qId = `${questionData.qIdPrefix || 'rand_'}_slot${slotIndex}_${Date.now()}_${randomPoolIdx}`;
                        questionData.qNumberDisplay = randomDisplayNumbersUntimed[k];
                        currentQuizQuestions[slotIndex] = questionData;
                    }
                }
            });
        }

        for (let i = 0; i < 10; i++) {
            if (!currentQuizQuestions[i]) {
                console.warn(`Slot ${i} (display ${i+1}) não foi preenchido, usando fallback.`);
                const fallbackPool = isTimedModeGlobal ?
                                   [...JSON.parse(JSON.stringify(baseFixedQuestions)), ...JSON.parse(JSON.stringify(randomizableQuestionPool))] :
                                   JSON.parse(JSON.stringify(randomizableQuestionPool));

                let fallbackQ = fallbackPool[Math.floor(Math.random() * fallbackPool.length)];
                let attempts = 0;
                while (currentQuizQuestions.some(q => q && q.stableId === fallbackQ.stableId && currentQuizQuestions.indexOf(q) !== i) && attempts < fallbackPool.length * 2) {
                    fallbackQ = fallbackPool[Math.floor(Math.random() * fallbackPool.length)];
                    attempts++;
                }
                const questionData = JSON.parse(JSON.stringify(fallbackQ));
                questionData.qId = `fallback_q${i}_${Date.now()}_${Math.random().toString(36).substring(7)}`;
                questionData.qNumberDisplay = (i + 1).toString();
                currentQuizQuestions[i] = questionData;
            }
        }
    }


    function initializeQuizInterfaceForNewAttempt() {
        buildCurrentQuiz();
        questionsState.length = 0;
        currentQuizQuestions.forEach(() => {
            questionsState.push({ userSelectedOptionIndex: null, isAnswered: false, isMarkedForReview: false });
        });
        quizFinalized = false;
        quizHeaderBackButton.style.display = 'block';

        if (timerIntervalGlobal) clearInterval(timerIntervalGlobal);
        timerIntervalGlobal = null;
        remainingSecondsGlobal = QUIZ_DURATION_SECONDS;

        if (isTimedModeGlobal) {
            console.log("MODO COM TEMPO ATIVADO - Timer e legenda devem ser ajustados.");
            timerDisplayContainer.style.display = 'block';
            probabilityLegendContainer.style.display = 'none';
             if(probabilityLegendTitle) probabilityLegendTitle.textContent = "Legenda de Destaque";
            startTimer();
        } else {
            console.log("MODO SEM TEMPO ATIVADO - Timer e legenda devem ser ajustados.");
            timerDisplayContainer.style.display = 'none';
            probabilityLegendContainer.style.display = 'block';
            if(probabilityLegendTitle) probabilityLegendTitle.textContent = "Legenda de Destaque (Modo SEM TEMPO):";
        }
        renderQuestions();
    }

    function navigateToModeSelection() {
        if (timerIntervalGlobal) {
            clearInterval(timerIntervalGlobal);
            timerIntervalGlobal = null;
            console.log("Timer parado ao voltar para seleção de modo.");
        }
        quizMainContainer.style.display = 'none';
        quizHeaderBackButton.style.display = 'none';
        modeSelectionScreen.classList.add('visible');
    }

    function startQuiz(timed) {
        console.log(`Iniciando quiz - Modo com tempo: ${timed}`);
        isTimedModeGlobal = timed;
        modeSelectionScreen.classList.remove('visible');
        quizMainContainer.style.display = 'flex';
        initializeQuizInterfaceForNewAttempt();
    }

    function renderQuestions() {
        console.log("Renderizando questões. Modo com tempo:", isTimedModeGlobal);
        questionsArea.innerHTML = '';
        navGrid.innerHTML = '';
        questionsArea.classList.remove('quiz-finalized');
        navGrid.classList.remove('quiz-finalized');

        if (!currentQuizQuestions || currentQuizQuestions.length === 0) {
            questionsArea.innerHTML = "<p>Erro ao carregar questões. Tente reiniciar.</p>";
            console.error("currentQuizQuestions está vazio ou indefinido em renderQuestions.");
            return;
        }

        currentQuizQuestions.forEach((qData, qIndex) => {
            if (!qData) {
                console.error(`Dados da questão indefinidos no índice ${qIndex} durante renderização.`);
                return;
            }

            const qBlock = document.createElement('div');
            qBlock.classList.add('question-block');
            qBlock.id = qData.qId;

            const qNum = document.createElement('span');
            qNum.classList.add('question-block-number');

            if (!isTimedModeGlobal) {
                // console.log(`Modo SEM TEMPO: Processando questão ${qData.qNumberDisplay} (${qData.stableId}) com topicKey: ${qData.topicKey} e highlight: ${qData.highlight}`);
                if (qData.topicKey && topicProbabilities[qData.topicKey]) {
                    const probInfo = topicProbabilities[qData.topicKey];
                    qBlock.classList.add(`prob-${probInfo.colorVarSuffix}`);
                    // console.log(`   Aplicada classe de bloco: prob-${probInfo.colorVarSuffix}`);
                }
                if (qData.highlight) {
                    qNum.style.color = 'var(--feedback-incorrect)'; // VERMELHO para número
                    // console.log(`   Número da questão ${qData.qNumberDisplay} em VERMELHO`);
                    if (!qBlock.classList.contains('prob-high')) {
                        qBlock.classList.add('important-question'); // Borda Laranja se não for já bloco vermelho
                        // console.log(`   Aplicada classe de borda: important-question`);
                    }
                }
            } else {
                // console.log(`Modo COM TEMPO: Questão ${qData.qNumberDisplay} (${qData.stableId}), sem destaques visuais.`);
            }

            qNum.textContent = `Questão ${qData.qNumberDisplay}`;
            const qHeader = document.createElement('div');
            qHeader.classList.add('question-block-header');
            qHeader.appendChild(qNum);
            const reviewBtn = document.createElement('button');
            reviewBtn.classList.add('question-block-review-btn');
            reviewBtn.textContent = questionsState[qIndex]?.isMarkedForReview ? `Desmarcar Revisão` : `Marcar para Revisão`;
            if (questionsState[qIndex]?.isMarkedForReview) reviewBtn.classList.add('marked');
            reviewBtn.disabled = quizFinalized;
            reviewBtn.addEventListener('click', () => toggleReview(qIndex));
            qHeader.appendChild(reviewBtn);

            const qText = document.createElement('div');
            qText.classList.add('question-block-text');
            qText.innerHTML = qData.text;
            if (qData.sourceRef) {
                const sourceSpan = document.createElement('span');
                sourceSpan.classList.add('source-reference');
                sourceSpan.textContent = qData.sourceRef;
                qText.appendChild(sourceSpan);
            }

            const qOptionsUl = document.createElement('ul');
            qOptionsUl.classList.add('question-block-options');
            if (qData.options && Array.isArray(qData.options)) {
                qData.options.forEach((opt, optIndex) => {
                    const optLi = document.createElement('li');
                    optLi.classList.add('option-item');
                    if (!quizFinalized && questionsState[qIndex]?.userSelectedOptionIndex === optIndex) {
                        optLi.classList.add('selected');
                    }
                    const optLetter = document.createElement('span');
                    optLetter.classList.add('option-letter');
                    optLetter.textContent = opt.id;
                    const optTextSpan = document.createElement('span');
                    optTextSpan.classList.add('option-text');
                    optTextSpan.innerHTML = opt.text;
                    optLi.appendChild(optLetter);
                    optLi.appendChild(optTextSpan);
                    optLi.addEventListener('click', () => {
                        // console.log(`Clique na opção: Questão ${qData.qNumberDisplay}, Opção ${opt.id}`);
                        selectOption(qIndex, optIndex);
                    });
                    qOptionsUl.appendChild(optLi);
                });
            }

            const feedbackDiv = document.createElement('div');
            feedbackDiv.classList.add('gabarito-feedback');
            feedbackDiv.style.display = 'none';
            qBlock.appendChild(qHeader);
            qBlock.appendChild(qText);
            qBlock.appendChild(qOptionsUl);
            qBlock.appendChild(feedbackDiv);
            questionsArea.appendChild(qBlock);

            const navBtn = document.createElement('button');
            navBtn.classList.add('nav-grid-button');
            navBtn.textContent = qData.qNumberDisplay;
            navBtn.addEventListener('click', () => {
                const targetElement = document.getElementById(qData.qId);
                if (targetElement) targetElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                else console.warn("Elemento de navegação não encontrado:", qData.qId);
            });
            if (questionsState[qIndex]?.isAnswered && !quizFinalized) navBtn.classList.add('answered');
            if (questionsState[qIndex]?.isMarkedForReview && !quizFinalized) navBtn.classList.add('review');
            navGrid.appendChild(navBtn);
        });
        finalizeButton.style.display = 'block';
        restartButton.style.display = 'none';
        finalizeButton.textContent = 'Finalizar Prova';
        updateStatusCounts();
    }

    function startTimer() {
        console.log("startTimer chamado");
        if (timerIntervalGlobal) clearInterval(timerIntervalGlobal);
        updateTimerDisplay();
        timerIntervalGlobal = setInterval(() => {
            remainingSecondsGlobal--;
            updateTimerDisplay();
            if (remainingSecondsGlobal < 0) {
                console.log("Tempo esgotado, finalizando quiz automaticamente.");
                autoFinalizeQuiz();
            }
        }, 1000);
    }

    function updateTimerDisplay() {
        const minutes = Math.max(0, Math.floor(remainingSecondsGlobal / 60));
        const seconds = Math.max(0, remainingSecondsGlobal % 60);
        if (timerDisplay) { // Verifica se timerDisplay existe
            timerDisplay.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
        }
    }

    function autoFinalizeQuiz() {
        if (timerIntervalGlobal) clearInterval(timerIntervalGlobal);
        timerIntervalGlobal = null;
        if (!quizFinalized) performFinalization(true);
    }

    function selectOption(qIndex, optIndex) {
        // console.log(`selectOption - qIndex: ${qIndex}, optIndex: ${optIndex}, quizFinalized: ${quizFinalized}`);
        if (quizFinalized) return;
        if (!questionsState[qIndex]) { console.error("Estado da questão indefinido em selectOption para índice:", qIndex); return; }
        if (!currentQuizQuestions[qIndex]) { console.error("Questão atual indefinida em selectOption para índice:", qIndex); return; }


        questionsState[qIndex].userSelectedOptionIndex = optIndex;
        questionsState[qIndex].isAnswered = true;

        const qBlock = document.getElementById(currentQuizQuestions[qIndex].qId);
        if (!qBlock) { console.error("Bloco da questão não encontrado em selectOption:", currentQuizQuestions[qIndex].qId); return; }
        const optionItems = qBlock.querySelectorAll('.option-item');
        optionItems.forEach((item, currentOptIndex) => item.classList.toggle('selected', currentOptIndex === optIndex));
        updateStatusCounts();
        updateNavGridButtonState(qIndex, false);
    }

    function toggleReview(qIndex) {
        if (quizFinalized) return;
        if (!questionsState[qIndex]) { console.error("Estado da questão indefinido em toggleReview para índice:", qIndex); return; }
        if (!currentQuizQuestions[qIndex]) { console.error("Questão atual indefinida em toggleReview para índice:", qIndex); return; }

        questionsState[qIndex].isMarkedForReview = !questionsState[qIndex].isMarkedForReview;

        const qBlock = document.getElementById(currentQuizQuestions[qIndex].qId);
        if (!qBlock) { console.error("Bloco da questão não encontrado em toggleReview:", currentQuizQuestions[qIndex].qId); return; }
        const reviewBtn = qBlock.querySelector('.question-block-review-btn');
        reviewBtn.textContent = questionsState[qIndex].isMarkedForReview ? `Desmarcar Revisão` : `Marcar para Revisão`;
        reviewBtn.classList.toggle('marked', questionsState[qIndex].isMarkedForReview);
        updateStatusCounts();
        updateNavGridButtonState(qIndex, false);
    }

    function updateStatusCounts() {
        let answered = 0, review = 0;
        const totalQs = currentQuizQuestions.length;

        if (totalQs > 0) {
            questionsState.forEach(qState => {
                if (qState && qState.isAnswered) answered++;
                if (qState && qState.isMarkedForReview) review++;
            });
            blankCountEl.textContent = totalQs - answered;
        } else {
            blankCountEl.textContent = 0; // Ou o número total esperado se não houver questões
        }
        answeredCountEl.textContent = answered;
        reviewCountEl.textContent = review;

        if (!quizFinalized) {
            finalizeButton.disabled = !(totalQs > 0 && answered === totalQs);
            finalizeButton.title = finalizeButton.disabled ? `Responda todas as ${totalQs > 0 ? totalQs : 10} questões para finalizar.` : "Finalizar a prova";
        }
    }

    function updateNavGridButtonState(qIndex, isFinalizedView) {
        const navButtons = navGrid.querySelectorAll('.nav-grid-button');
        if (!currentQuizQuestions || !currentQuizQuestions[qIndex]) return;
        const targetNavButton = Array.from(navButtons).find(btn => btn.textContent === currentQuizQuestions[qIndex].qNumberDisplay);
        if (targetNavButton) {
            targetNavButton.className = 'nav-grid-button';
            if (isFinalizedView) {
                const userChoiceIndex = questionsState[qIndex]?.userSelectedOptionIndex;
                const correctOptionIndex = currentQuizQuestions[qIndex].options.findIndex(opt => opt.isCorrect);
                if (userChoiceIndex === null || typeof userChoiceIndex === 'undefined') targetNavButton.classList.add('nav-grid-unanswered');
                else if (userChoiceIndex === correctOptionIndex) targetNavButton.classList.add('nav-grid-correct');
                else targetNavButton.classList.add('nav-grid-incorrect');
            } else {
                if (questionsState[qIndex]?.isAnswered) targetNavButton.classList.add('answered');
                if (questionsState[qIndex]?.isMarkedForReview) targetNavButton.classList.add('review');
            }
        }
    }

    function performFinalization(isAutoFinalized = false) {
        if (quizFinalized && !isAutoFinalized) return;
        if (quizFinalized && isAutoFinalized && finalizeButton.disabled) return;

        quizFinalized = true;
        quizHeaderBackButton.style.display = 'none';
        if (timerIntervalGlobal && !isAutoFinalized) {
            clearInterval(timerIntervalGlobal);
            timerIntervalGlobal = null;
            console.log("Timer parado ao finalizar manualmente.");
        } else if (timerIntervalGlobal && isAutoFinalized) {
             clearInterval(timerIntervalGlobal); // Garante que parou se foi auto-finalizado
            timerIntervalGlobal = null;
            console.log("Timer parado por auto-finalização.");
        }

        finalizeButton.disabled = true;
        finalizeButton.textContent = 'Prova Finalizada';
        finalizeButton.style.display = 'none';
        restartButton.style.display = 'block';
        questionsArea.classList.add('quiz-finalized');
        navGrid.classList.add('quiz-finalized');
        document.querySelectorAll('.question-block-review-btn').forEach(btn => btn.disabled = true);
        let correctAnswersCount = 0;
        currentQuizQuestions.forEach((qData, qIndex) => {
            const qBlock = document.getElementById(qData.qId);
            if (!qBlock) { console.error("Bloco da questão não encontrado para finalização:", qData.qId); return; }
            const optionItems = qBlock.querySelectorAll('.option-item');
            const feedbackDiv = qBlock.querySelector('.gabarito-feedback');
             if (!feedbackDiv) { console.error("Div de feedback não encontrada para:", qData.qId); return; }

            const userChoiceIndex = questionsState[qIndex]?.userSelectedOptionIndex;
            const correctOptionObj = qData.options.find(opt => opt.isCorrect);
            const correctOptionIndex = qData.options.indexOf(correctOptionObj);
            let feedbackHTML = ``;
            if (userChoiceIndex !== null && typeof userChoiceIndex !== 'undefined') {
                const isUserCorrect = userChoiceIndex === correctOptionIndex;
                if(isUserCorrect) correctAnswersCount++;
                feedbackHTML += `<p><strong>Sua resposta:</strong> Opção ${qData.options[userChoiceIndex]?.id || 'Inválida'}</p>`;
                if (isUserCorrect) {
                    feedbackDiv.className = 'gabarito-feedback correct';
                    feedbackHTML += `<p><strong>Resultado:</strong> Correto!</p>`;
                    if(optionItems[userChoiceIndex]) optionItems[userChoiceIndex].classList.add('user-correct');
                } else {
                    feedbackDiv.className = 'gabarito-feedback incorrect';
                    feedbackHTML += `<p><strong>Resultado:</strong> Incorreto.</p>`;
                    if(optionItems[userChoiceIndex]) optionItems[userChoiceIndex].classList.add('user-incorrect');
                }
            } else {
                feedbackDiv.className = 'gabarito-feedback incorrect';
                feedbackHTML += `<p><strong>Sua resposta:</strong> Nenhuma opção selecionada.</p>`;
                feedbackHTML += `<p><strong>Resultado:</strong> Incorreto.</p>`;
            }
            feedbackHTML += `<p><strong>Resposta correta:</strong> Opção ${correctOptionObj.id} - ${correctOptionObj.text}</p>`;
            if (qData.gabaritoComentado) feedbackHTML += `<p class="gabarito-comentario"><strong>Comentário:</strong> ${qData.gabaritoComentado}</p>`;
            feedbackDiv.innerHTML = feedbackHTML;
            feedbackDiv.style.display = 'block';
            if (correctOptionIndex !== -1 && optionItems[correctOptionIndex]) optionItems[correctOptionIndex].classList.add('actual-correct');
            optionItems.forEach(optItem => { optItem.style.cursor = 'default'; optItem.classList.remove('selected'); });
            updateNavGridButtonState(qIndex, true);
        });
        if (isAutoFinalized) {
            const timeUpMsg = document.createElement('div');
            timeUpMsg.innerHTML = `<h3>Tempo Esgotado!</h3><p>Sua prova foi finalizada automaticamente.</p>`;
            timeUpMsg.style.cssText = "background-color: var(--feedback-incorrect-bg); color: var(--feedback-incorrect-text); border: 1px solid var(--feedback-incorrect); padding: 15px; border-radius: var(--border-radius-md); text-align: center; font-weight: bold; margin-bottom: 20px;";
            const firstQuestionBlock = questionsArea.querySelector('.question-block');
            if (firstQuestionBlock) questionsArea.insertBefore(timeUpMsg, firstQuestionBlock);
            else questionsArea.appendChild(timeUpMsg);
        }
    }

    finalizeButton.addEventListener('click', () => performFinalization(false));
    restartButton.addEventListener('click', navigateToModeSelection);
    quizHeaderBackButton.addEventListener('click', navigateToModeSelection);
    themeToggleButton.addEventListener('click', () => {
        document.body.classList.toggle('dark-theme');
        const isDarkMode = document.body.classList.contains('dark-theme');
        localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
        themeToggleButton.textContent = isDarkMode ? '☀️' : '🌙';
    });
    startTimedButton.addEventListener('click', () => startQuiz(true));
    startUntimedButton.addEventListener('click', () => startQuiz(false));
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
        document.body.classList.add('dark-theme');
        themeToggleButton.textContent = '☀️';
    } else {
        document.body.classList.remove('dark-theme');
        themeToggleButton.textContent = '🌙';
    }
    navigateToModeSelection();
});
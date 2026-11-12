---
name: diagnostico-seguranca
description: Roda avaliação de comprometimento e diagnóstico de segurança dos ativos da empresa (Cloudflare, AWS, Google Cloud, Supabase, GitHub, Microsoft 365, servidores Linux/Windows/AD, aplicações, senhas expostas, DDoS), com caminhos de ataque e comparação com a execução anterior. Use para "diagnóstico de segurança", "auditoria", "pontos de ataque", "fomos invadidos?", "senhas vazadas".
---

# Diagnóstico de segurança

Auditoria defensiva dos ativos da própria empresa. Responde a duas perguntas distintas, nesta ordem: **(1) ainda há invasor dentro?** e **(2) por onde entrariam de novo?** Termina com os caminhos de ataque encadeados e um relatório comparável com a execução anterior.

## Regras

1. **Somente ativos da empresa**, confirmados no Passo 0. Nunca varrer terceiros, fornecedores ou os atacantes.
2. **Dois níveis de execução.**
   - **Nível A (padrão): somente leitura.** Nada é alterado, criado ou apagado.
   - **Nível B: testes ativos.** Itens marcados com **[B]**. Só rodam com autorização explícita da pessoa nesta conversa, citando o alvo e a janela, e de preferência em homologação. Sem autorização, o item entra como NÃO VERIFICADO.
3. **Sem exploração.** Demonstre que a falha existe com o mínimo necessário (ex.: uma leitura com usuário de teste) e pare. Não extraia dados reais, não quebre senhas, não teste credenciais vazadas em sistemas.
4. **Segredos nunca em claro.** Registre local, tipo e os 4 últimos caracteres. O próprio resultado da auditoria é sensível: guarde-o só onde a pessoa indicar.
5. **Nunca peça nem receba senhas de colaboradores.**
6. **Sem acesso não é aprovado.** Módulo sem credencial, ferramenta ou alcance vira NÃO VERIFICADO, com o que falta.
7. **Indício de invasor ativo interrompe o fluxo**: avise imediatamente, recomende preservar evidência (snapshot de disco, exportação de logs) antes de qualquer limpeza, e só então continue.
8. **Host suspeito não é fonte confiável.** Saída de comando rodado numa máquina possivelmente comprometida pode estar falsificada; cruze sempre com uma visão externa (Passo 1.6).
9. Correções são propostas, não aplicadas, salvo pedido explícito item a item.

## Como executar

- **Coletores, não comandos soltos.** Para cada plataforma, grave no diretório de trabalho um script de coleta (`coleta_aws.sh`, `coleta_gcp.sh`, `coleta_linux.sh`, `coleta_windows.ps1`, `coleta_m365.ps1`, `coleta_cloudflare.sh`) que roda os comandos deste documento com saída em JSON (`--output json`, `--format=json`, `ConvertTo-Json -Depth 6`) para `coleta/<plataforma>/<check>.json`. Analise os arquivos, não a tela. Para servidores sem alcance direto, entregue o script ao administrador e analise o arquivo devolvido.
- **Todas as contas, projetos e regiões**: itere `aws ec2 describe-regions` e `gcloud projects list`. Uma região não usada com recurso rodando é achado.
- Módulos independentes podem rodar em paralelo.
- Credenciais de auditoria, de curta duração: AWS `SecurityAudit` + `ViewOnlyAccess`; GCP `roles/iam.securityReviewer` + `roles/viewer` (+ `roles/cloudasset.viewer`); Microsoft 365 `Global Reader` + `Security Reader`; Cloudflare token somente-leitura (Zone, DNS, Firewall Services, Zone Settings, Logs, Account Settings: Read); Supabase e GitHub pelos conectores.

## Passo 0 — Escopo e inventário autoritativo

Registre: domínios, contas AWS, projetos GCP, projetos Supabase, organização GitHub, tenant Microsoft 365, zonas Cloudflare, servidores locais, **janela do incidente** (início/fim com fuso) e a pasta onde ficam relatório e baseline.

O inventário de exposição vem das APIs, não de suposição:

```bash
# AWS (por região)
aws ec2 describe-network-interfaces --query 'NetworkInterfaces[?Association.PublicIp].[NetworkInterfaceId,Association.PublicIp,Description]'
aws ec2 describe-addresses
aws elbv2 describe-load-balancers --query 'LoadBalancers[?Scheme==`internet-facing`].[LoadBalancerName,DNSName]'
aws apigateway get-rest-apis; aws apigatewayv2 get-apis
aws cloudfront list-distributions --query 'DistributionList.Items[].[Id,DomainName,Origins.Items[0].DomainName]'
aws lambda list-functions --query 'Functions[].FunctionName'   # depois: aws lambda list-function-url-configs --function-name <f>  (AuthType NONE = público)
# GCP (por projeto)
gcloud compute addresses list --format=json
gcloud compute forwarding-rules list --format=json
gcloud run services list --format=json; gcloud functions list --format=json
gcloud asset search-all-resources --scope=projects/<PROJETO> --asset-types=compute.googleapis.com/Instance,sqladmin.googleapis.com/Instance,storage.googleapis.com/Bucket
```

Some: registros DNS da Cloudflare, subdomínios de certificate transparency (crt.sh), URLs diretas do Supabase, IPs dos servidores locais, endereços **IPv6**. Todo ativo público sem dono conhecido é achado.

---

# Fase 1 — Avaliação de comprometimento (ainda há invasor?)

Foco na janela do incidente e nos 30 dias anteriores. Procure **persistência**: o que o invasor deixou para voltar depois da troca de senhas. Monte uma linha do tempo única (UTC) cruzando todas as fontes e uma lista de indicadores (IPs, ASNs, user-agents, contas, chaves).

## 1.1 Microsoft 365 / Entra (vetor inicial provável)

```powershell
Get-MgAuditLogSignIn -Filter "createdDateTime ge <inicio>" -All   # IP, país, clientAppUsed, deviceDetail, riskLevel, conditionalAccessStatus
Search-UnifiedAuditLog -StartDate <inicio> -EndDate <fim> -ResultSize 5000 -Operations MailItemsAccessed,New-InboxRule,Set-InboxRule,Add-MailboxPermission,Set-Mailbox,"Consent to application.","Add service principal credentials.","Add app role assignment to service principal.","User registered security info","Add member to role."
Get-MgApplication -All | Select DisplayName,AppId,CreatedDateTime,PasswordCredentials,KeyCredentials
Get-MgServicePrincipal -All | Select DisplayName,AppId,ServicePrincipalType,AccountEnabled
Get-MgOauth2PermissionGrant -All
Get-MgUserAuthenticationMethod -UserId <upn>          # para cada conta afetada e cada admin
Get-Mailbox -ResultSize Unlimited | % { Get-InboxRule -Mailbox $_.UserPrincipalName } | ? { $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo -or $_.DeleteMessage -or $_.MoveToFolder }
Get-Mailbox -ResultSize Unlimited | Select UserPrincipalName,ForwardingSmtpAddress,ForwardingAddress
Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | ? { -not $_.IsInherited -and $_.User -notlike 'NT AUTHORITY*' }
```

Persistência típica: método de MFA (telefone, app autenticador) registrado pelo invasor; credencial nova em app registration existente; consentimento OAuth com `Mail.Read`, `Files.Read.All` ou `offline_access`; regra de caixa que encaminha, move para RSS/Arquivo ou apaga; delegação de caixa; conta convidada nova; papel de admin atribuído. `MailItemsAccessed` mostra quais mensagens foram lidas, o que define o alcance do vazamento. Sessão de login com MFA satisfeito a partir de IP de hospedagem/proxy indica roubo de token (phishing AiTM): trocar a senha não basta, é preciso revogar sessões.

## 1.2 AWS

```bash
for e in ConsoleLogin CreateUser CreateAccessKey CreateLoginProfile UpdateLoginProfile AttachUserPolicy AttachRolePolicy PutUserPolicy PutRolePolicy CreatePolicyVersion UpdateAssumeRolePolicy CreateRole CreateOpenIDConnectProvider CreateSAMLProvider UpdateFunctionCode20150331v2 CreateFunction20150331 ModifyInstanceAttribute RunInstances SendCommand AuthorizeSecurityGroupIngress PutBucketPolicy GetSecretValue StopLogging DeleteTrail PutEventSelectors GetFederationToken; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$e --start-time <inicio> --end-time <fim> --output json > coleta/aws/ct_$e.json
done
aws iam list-roles --query 'Roles[].[RoleName,CreateDate,AssumeRolePolicyDocument]'   # trust policy com conta externa ou Principal "*"
aws iam list-open-id-connect-providers; aws iam list-saml-providers
aws iam list-users --query 'Users[].[UserName,CreateDate,PasswordLastUsed]'           # depois list-access-keys por usuário
aws lambda list-functions --query 'Functions[].[FunctionName,LastModified,Role]'      # depois get-policy por função
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,LaunchTime,IamInstanceProfile.Arn,KeyName]'
aws ec2 describe-instance-attribute --instance-id <id> --attribute userData
aws accessanalyzer list-analyzers   # depois list-findings: recursos compartilhados com fora da conta
```

Persistência típica: usuário/chave novos; trust policy de role alterada para conta externa; provedor de identidade federada novo; Lambda ou user-data alterados; instâncias em região não usada (mineração); snapshot/AMI compartilhados; `StopLogging`. `GetSecretValue` e leituras de S3 em massa indicam o que foi levado.

## 1.3 Google Cloud

```bash
gcloud logging read 'protoPayload.methodName:("SetIamPolicy" OR "CreateServiceAccountKey" OR "CreateServiceAccount" OR "GenerateAccessToken" OR "setMetadata" OR "compute.instances.insert" OR "firewalls.insert" OR "firewalls.patch") AND timestamp>="<inicio>"' --project <PROJETO> --format=json
gcloud projects get-iam-policy <PROJETO> --format=json
gcloud iam service-accounts keys list --iam-account <SA> --format=json     # validAfterTime na janela
gcloud compute project-info describe --format="json(commonInstanceMetadata.items)"   # chaves SSH em metadados do projeto
gcloud compute instances list --format="json(name,creationTimestamp,metadata.items,serviceAccounts)"
```

Persistência típica: chave de service account criada; binding novo em `roles/owner`, `roles/iam.serviceAccountTokenCreator` ou para conta externa; chave SSH injetada em metadados; startup-script alterado; VM nova.

## 1.4 Supabase (via `execute_sql`, só SELECT, e `query_logs`)

```sql
select rolname, rolsuper, rolcreaterole, rolbypassrls, rolcanlogin from pg_roles where rolname !~ '^pg_';
select n.nspname, p.proname, p.prosecdef, pg_get_userbyid(p.proowner) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname not in ('pg_catalog','information_schema') order by p.oid desc limit 100;
select tgname, tgrelid::regclass, tgenabled, tgfoid::regproc from pg_trigger where not tgisinternal;
select * from cron.job;                          -- se pg_cron existir
select * from supabase_functions.hooks order by id desc limit 50;   -- webhooks de banco, se existir
select count(*) filter (where created_at >= '<inicio>') as novos, count(*) as total from auth.users;
```

Persistência típica: role com login ou `bypassrls` desconhecida; função `SECURITY DEFINER`, trigger, job de cron ou webhook que envia dados para fora (`pg_net`, `http`); usuário promovido a admin na tabela de perfis; Edge Function alterada (`list_edge_functions`); chaves de API novas.

## 1.5 GitHub

Audit log da organização na janela: membros e colaboradores adicionados, deploy keys, tokens (PAT/fine-grained) e GitHub Apps autorizados, webhooks, mudança de visibilidade de repositório, alteração de proteção de branch, mudanças em `.github/workflows/` (use `list_commits` por caminho). Um workflow alterado que imprime ou envia `secrets.*` significa que todos os segredos do repositório vazaram.

## 1.6 Servidores Linux

```bash
systemctl list-unit-files --state=enabled --no-pager
find /etc/systemd /usr/lib/systemd /lib/systemd /home/*/.config/systemd /root/.config/systemd -type f -newermt "<inicio>" 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/ld.so.conf.d
find /etc/pam.d /lib/*/security /usr/lib/*/security -type f -newermt "<inicio>" 2>/dev/null
debsums -c 2>/dev/null || rpm -Va 2>/dev/null          # binários de pacote alterados
find /home /root -name authorized_keys -exec ls -l {} \; -exec cat {} \;
awk -F: '$3==0{print $1}' /etc/passwd; ls -la /etc/sudoers.d; getcap -r / 2>/dev/null
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null; done; ls -la /etc/cron.* /etc/profile.d
find /etc /usr/bin /usr/sbin /usr/local/bin -xdev -type f -newermt "<inicio>" 2>/dev/null
ls -la /tmp /dev/shm /var/tmp; lsmod
ss -tnp state established; ss -tulpn
last -n 100; lastb -n 100; journalctl -u ssh -u sshd --since "<inicio>" | grep -Ei 'accepted|failed'
```

**Visão externa obrigatória**: compare as portas que `ss` mostra com um `nmap` feito de fora, e os processos de `ps` com as entradas de `/proc`. Divergência sugere rootkit: nesse caso a máquina deve ser analisada por snapshot de disco montado em outra instância e reconstruída, não limpa.

## 1.7 Servidores Windows e Active Directory

```powershell
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-CimInstance Win32_Service | ? { $_.PathName -notmatch 'Windows\\' } | Select Name,PathName,StartName,StartMode
Get-ScheduledTask | ? { $_.TaskPath -notlike '\Microsoft\*' } | Select TaskName,TaskPath,@{n='Acao';e={$_.Actions.Execute}}
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime='<inicio>'}                       # serviço instalado
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698,4720,4728,4732,4756,1102;StartTime='<inicio>'}  # tarefa criada, conta criada, grupo privilegiado, log apagado
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime='<inicio>'} | Group {$_.Properties[19].Value} | Sort Count -Desc
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime='<inicio>'} | ? { $_.Properties[8].Value -in 3,10 }
Get-ADUser krbtgt -Properties PasswordLastSet
Get-ADGroupMember 'Domain Admins' -Recursive; Get-ADGroupMember 'Enterprise Admins' -Recursive
Get-ADUser -Filter * -Properties whenCreated,SIDHistory,adminCount | ? { $_.whenCreated -ge '<inicio>' -or $_.SIDHistory }
```

Se um controlador de domínio ou conta de Domain Admin foi tocado, presuma roubo do `krbtgt` (golden ticket): a correção é redefinir a senha do `krbtgt` duas vezes, com intervalo maior que a validade dos tickets.

## 1.8 Cloudflare

Audit Log da conta na janela (DNS alterado, regra de WAF desativada, token criado, membro adicionado) e eventos de segurança: principais IPs, ASNs, países, caminhos e user-agents. Esses indicadores alimentam a busca nos demais logs.

**Saída da Fase 1**: veredito por plataforma (Sem indícios / Indícios / Comprometida / Não verificado), linha do tempo, indicadores, o que foi acessado ou levado, e a lista de credenciais que precisam ser rotacionadas.

---

# Fase 2 — Postura (por onde entrariam de novo?)

## 2.1 Superfície externa

Sobre o inventário do Passo 0:

- TCP completo nos IPs públicos: `nmap -Pn -sV -p- <ip>`; UDP nos serviços de amplificação: `nmap -Pn -sU -p 53,123,161,389,1900,5353,11211 <ip>` (servidor que responde nessas portas pode ser usado como refletor de DDoS); repita em IPv6 (`-6`).
- Críticos se abertos à internet: 22, 3389, 445, 5985/5986, 1433/3306/5432/6543/27017/6379/9200, 2375, 5900, 10250, painéis de administração.
- Como os atacantes já veem a empresa: consulte Shodan/Censys pelos próprios IPs e domínios.
- Subdomínio apontando para recurso apagado (CNAME para bucket, app ou IP liberado) = takeover.
- TLS (`testssl.sh`), cabeçalhos (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), banner de versão.
- Arquivos expostos: `/.git/config`, `/.env`, backups, `phpinfo`, listagem de diretório, Swagger/OpenAPI, `/actuator`, `/metrics`, `/debug`.
- E-mail: SPF, DKIM, DMARC (`p=none` ou ausente é achado), MTA-STS.

## 2.2 AWS

Base: `prowler aws` (CIS). Mínimo por CLI:

```bash
aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d
aws iam get-account-summary; aws iam get-account-password-policy
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,MetadataOptions.HttpTokens]'   # IMDSv2: required
aws s3control get-public-access-block --account-id <ID>     # e por bucket: get-public-access-block, get-bucket-policy-status, get-bucket-encryption, get-bucket-logging
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,PubliclyAccessible,StorageEncrypted]'
aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all     # snapshots públicos
aws cloudtrail describe-trails; aws guardduty list-detectors; aws securityhub describe-hub; aws shield describe-subscription
aws secretsmanager list-secrets --query 'SecretList[].[Name,LastRotatedDate]'
```

Procure também: root com chave ou sem MFA, chaves com mais de 90 dias, usuários IAM onde deveria haver SSO, segredos em variáveis de ambiente de Lambda/ECS e em user-data, CloudTrail sem multi-região ou sem validação de log, VPC Flow Logs ausentes.

## 2.3 Google Cloud

Base: `prowler gcp`. Mínimo:

```bash
gcloud projects get-iam-policy <PROJETO> --format=json      # allUsers, allAuthenticatedUsers, owner/editor em excesso, contas externas
gcloud compute firewall-rules list --filter="direction=INGRESS AND sourceRanges:0.0.0.0/0" --format=json
gcloud compute instances list --format="json(name,networkInterfaces[].accessConfigs[].natIP,serviceAccounts,metadata.items)"
gcloud storage buckets list --format="value(name)"          # depois get-iam-policy por bucket
gcloud sql instances list --format=json                      # authorizedNetworks 0.0.0.0/0, requireSsl
gcloud logging sinks list; gcloud services list --enabled
```

Procure: service account padrão com escopo `cloud-platform`, chaves de service account baixadas, OS Login desligado, Data Access logs desligados, Cloud SQL com IP público.

## 2.4 Supabase

`get_advisors` (security) é a base. Depois, por SQL somente-leitura:

```sql
select schemaname, tablename from pg_tables where schemaname not in ('pg_catalog','information_schema','auth','storage','realtime','vault','extensions') and not rowsecurity;
select schemaname, tablename, policyname, roles, cmd, qual, with_check from pg_policies;
select table_schema, table_name, grantee, privilege_type from information_schema.role_table_grants where grantee in ('anon','authenticated','public');
select c.relname, c.reloptions from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind='v' and n.nspname='public';   -- view sem security_invoker=true ignora o RLS
select n.nspname, p.proname, p.proconfig from pg_proc p join pg_namespace n on n.oid=p.pronamespace where p.prosecdef and n.nspname not in ('pg_catalog','information_schema');
select id, name, public from storage.buckets;
```

Procure: tabela sem RLS; policy `USING (true)` ou que confia em campo editável pelo usuário (ex.: `user_metadata`); policy de UPDATE sem `WITH CHECK`; view sem `security_invoker`; função `SECURITY DEFINER` sem `search_path` fixo e executável por `anon`; schemas expostos além do necessário; `service_role` em front-end ou repositório; banco acessível direto (5432/6543) sem restrição de rede e sem SSL obrigatório; Auth sem confirmação de e-mail, sem proteção contra senha vazada, sem limites de taxa, JWT com validade longa; Edge Functions sem verificação de JWT.

**[B] Teste real de RLS**: com a chave `anon` e dois usuários de teste, tente ler e alterar registros do outro usuário em cada tabela exposta. É a única prova de que as policies funcionam.

## 2.5 GitHub e cadeia de suprimentos

- Segredos: `run_secret_scanning`; em clone local `gitleaks detect --redact` (histórico inteiro). Segredo encontrado = comprometido, rotacionar.
- Organização: 2FA obrigatório, colaboradores externos, ex-funcionários, admins em excesso, deploy keys e tokens antigos, apps autorizados, webhooks.
- Branch principal protegida (review obrigatório, sem force-push, commits assinados se possível).
- **Actions**: `pull_request_target` com checkout do código do PR; `permissions` do `GITHUB_TOKEN` amplas; actions de terceiros sem fixar por SHA; runners self-hosted em repositório público; segredos de longa duração para nuvem. Recomendação padrão: **federação OIDC** do GitHub Actions para AWS e GCP, eliminando chaves estáticas.
- Dependências e imagens: Dependabot, `npm audit`, `pip-audit`, `trivy fs .`, `trivy image <img>`, `grype`. Infraestrutura como código: `checkov -d .` ou `trivy config .`. Código: `semgrep --config auto`.
- Fora da organização: `search_code` público pelo domínio da empresa, nomes de projetos internos e prefixos de chave, para achar código em repositórios pessoais de colaboradores.

## 2.6 Identidade (Microsoft 365 / Entra)

```powershell
Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Select UserPrincipalName,IsAdmin,IsMfaRegistered,IsMfaCapable,MethodsRegistered
Get-MgIdentityConditionalAccessPolicy | Select DisplayName,State,Conditions,GrantControls,SessionControls
Get-MgPolicyAuthorizationPolicy | Select -Expand DefaultUserRolePermissions     # usuários podem consentir apps / registrar apps?
Get-MgDirectoryRole | % { $r=$_; Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id | Select @{n='Papel';e={$r.DisplayName}},Id }
Get-MgRiskyUser -All; Get-MgUser -Filter "userType eq 'Guest'" -All
Get-OrganizationConfig | Select AuditDisabled; Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled
```

MFA comum (SMS, push, código) não resiste a phishing com proxy nem a roubo de token. Avalie:

- **MFA resistente a phishing** (FIDO2/passkeys, Windows Hello) obrigatório para administradores e, em seguida, para todos.
- Conditional Access: bloquear autenticação legada; exigir dispositivo gerenciado/conforme para apps sensíveis; políticas por risco de login e de usuário; frequência de sessão; proteção de token e avaliação contínua de acesso; nenhuma exclusão ampla além de contas de emergência.
- Consentimento de usuário a apps OAuth desligado ou restrito a publicadores verificados.
- Administradores: 2 a 4 globais, contas separadas das de uso diário, PIM/acesso just-in-time, duas contas de emergência monitoradas.
- Proteção de senha do Entra (lista banida personalizada), detecção de credenciais vazadas do Entra ID Protection, SSPR.
- Unified Audit Log ligado e retido; auditoria de caixa de correio.
- SSO: quais sistemas (AWS, GCP, GitHub, Cloudflare, Supabase) ainda usam senha local em vez de login federado.

## 2.7 Senhas e credenciais expostas

- Have I Been Pwned, busca por domínio verificado: quais e-mails corporativos em quais vazamentos.
- Logs de infostealer (malware que rouba senhas e cookies do navegador): consultar serviço de threat intel pelo domínio. É a fonte mais provável quando contas com MFA são invadidas. Máquina que aparece ali precisa ser reinstalada.
- E-mails pessoais: a empresa não coleta nem consulta; orienta cada pessoa a checar o próprio em haveibeenpwned.com.
- Senha específica: só o dono, via Pwned Passwords com k-anonimato (5 primeiros caracteres do SHA-1 para `https://api.pwnedpasswords.com/range/<prefixo>`).
- AD: auditoria de senhas fracas/vazadas feita pelo administrador do domínio contra a lista de hashes do HIBP, sem expor hashes fora do controlador.
- Senhas em texto: busca no SharePoint/Teams/repositórios por "senha", "password", "acesso", "credenciais".
- **Honeytokens**: recomendar chave AWS sem permissão com alarme no CloudTrail, conta-isca no AD e arquivo-isca de credenciais. Uso de qualquer um é alerta certo de invasão.
- Estrutural: gerenciador de senhas corporativo, SSO, MFA resistente a phishing.

## 2.8 Servidores Linux

Além da Fase 1.6:

```bash
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|port '
ufw status verbose || nft list ruleset || iptables -S
apt list --upgradable 2>/dev/null || dnf check-update; uname -r; cat /etc/os-release
dpkg -l 2>/dev/null || rpm -qa        # inventário de pacotes para o módulo 2.12
find / -xdev -perm -4000 -type f 2>/dev/null
docker ps --format json 2>/dev/null; ls -l /var/run/docker.sock; sysctl kernel.unprivileged_userns_clone net.ipv4.ip_forward 2>/dev/null
systemctl is-active auditd fail2ban crowdsec 2>/dev/null
```

Procure: SSH por senha ou root; serviços em 0.0.0.0 que deveriam ser internos; SO fora de suporte; contêiner privilegiado ou com docker.sock montado; sem auditd; logs só locais; base CIS (`lynis audit system`).

## 2.9 Servidores Windows e Active Directory

```powershell
Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess | Sort LocalPort
Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction
Get-LocalGroupMember Administrators; Get-HotFix | Sort InstalledOn -Desc | Select -First 10
Get-SmbServerConfiguration | Select EnableSMB1Protocol,RequireSecuritySignature
Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated
(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication   # 1 = NLA
(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa').LmCompatibilityLevel; (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa').RunAsPPL
Get-ADDefaultDomainPasswordPolicy
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName,PasswordLastSet,MemberOf      # alvos de Kerberoasting
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'                                                              # alvos de AS-REP roasting
Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation                          # delegação irrestrita
Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true'
```

Base recomendada para o AD: relatório do **PingCastle** (somente leitura) e **Locksmith** para modelos de certificado do AD CS. Procure: RDP/SMB/WinRM alcançáveis da internet, NTLMv1 e SMBv1, LAPS ausente, contas de serviço com SPN em grupos privilegiados e senha antiga, direitos de replicação (DCSync) fora dos controladores, LSA Protection desligada, log de segurança pequeno demais, Sysmon/EDR ausente.

## 2.10 Cloudflare, DDoS e robôs

- **Registros sem proxy** (`GET /zones/<id>/dns_records`, `proxied=false`) que apontam para servidor da empresa revelam o IP de origem. Atenção a `mail`, `ftp`, `dev`, `staging`, `direct`, `origin` e a MX no mesmo IP do site.
- **Origem trancada**: firewall da AWS, GCP e servidores locais aceitando 80/443 só das faixas da Cloudflare (https://www.cloudflare.com/ips/), ou Cloudflare Tunnel / Authenticated Origin Pulls. Teste: `curl -k --resolve dominio:443:<ip-origem> https://dominio/` de fora não pode responder. Origem aberta = o ataque contorna a Cloudflare.
- **Camadas**: o proxy da Cloudflare protege HTTP/HTTPS. Serviços não-HTTP (SSH, banco, e-mail, jogos, VPN) e IPs diretos continuam expostos a ataque volumétrico (camadas 3/4), a não ser com Spectrum/Magic Transit ou proteção do provedor (AWS Shield, Cloud Armor).
- **O que não passa pela Cloudflare**: URL direta do Supabase, URLs padrão de load balancer, API Gateway, Cloud Run e function URLs do inventário.
- SSL/TLS em Full (strict) (Flexible é Alto), TLS mínimo 1.2, HSTS, DNSSEC.
- WAF: Managed Ruleset e OWASP em bloqueio, não só log; exceções e allowlists em excesso; HTTP DDoS Managed Ruleset; Bot Fight Mode; rate limiting em login, cadastro, recuperação de senha, busca e APIs; regras contra cache-busting (query string aleatória) em rotas cacheáveis.
- Conta: 2FA obrigatório, membros e tokens em excesso, Global API Key em uso.
- Painéis, SSH e RDP atrás de Cloudflare Access (Zero Trust).
- Aplicação: endpoints caros com cache, paginação, autenticação e limite; autoscaling com teto; alarme de custo.

## 2.11 Aplicações e APIs (o que os robôs procuram)

Somente leitura:

- Inventário de rotas (OpenAPI, código, logs da Cloudflare): rotas sem autenticação, rotas antigas (`/v1`, `/old`, `/test`), GraphQL com introspecção ligada em produção.
- CORS: `curl -sI -H "Origin: https://exemplo-externo.test" <url>`; origem refletida junto com `Access-Control-Allow-Credentials: true` é Alto.
- Sessão e JWT: algoritmo, validade, rotação do segredo, cookies com `Secure`, `HttpOnly`, `SameSite`.
- Revisão de código (semgrep + leitura) para o OWASP API Top 10: verificação de dono do objeto em cada rota com ID (BOLA/IDOR), atribuição em massa (corpo da requisição gravado direto no banco), injeção de SQL/comando, upload sem validação, e **SSRF**: todo ponto que busca uma URL fornecida pelo usuário pode alcançar o serviço de metadados da nuvem e roubar credenciais da instância. Mitigação a verificar: IMDSv2 obrigatório, lista de destinos permitidos, bloqueio de saída para 169.254.169.254.
- Mensagens de erro com stack trace; enumeração de usuários no login e na recuperação de senha.

**[B]**, em homologação, com contas de teste: ZAP baseline (`zap-baseline.py -t <url>`), `nuclei` com modelos não intrusivos, teste de BOLA com dois usuários, verificação de limite de taxa no login.

## 2.12 Vulnerabilidades priorizadas por exploração real

"Patches pendentes" não é achado suficiente. Para cada software exposto (versões do `nmap -sV`, pacotes dos servidores, imagens, dependências):

1. Mapear versão para CVE (Trivy, Grype, OSV, avisos do fornecedor).
2. Cruzar com o catálogo **CISA KEV** (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) e com o **EPSS** (`https://api.first.org/data/v1/epss?cve=<CVE>`).
3. Prioridade: em KEV e exposto à internet = Crítico; EPSS acima de 0,5 e exposto = Alto; demais conforme CVSS e alcance.

Atenção especial a equipamentos de borda (VPN, firewall, roteador), que não aparecem em inventário de servidor e são alvo preferido.

## 2.13 Detecção, backup e resposta

- Logs centralizados fora do alcance do invasor (conta/projeto separado, retenção mínima de 90 dias): CloudTrail, GCP Audit, Entra, Cloudflare, Supabase, servidores.
- Alertas com destinatário real para: login de admin, usuário/chave/role criados, mudança de firewall, log desligado, consentimento OAuth, regra de encaminhamento, login de país novo.
- Backups isolados e imutáveis (outra conta, Object Lock), com restauração testada e data do último teste.
- Processo de desligamento de colaboradores; inventário de quem acessa o quê.
- Plano de resposta escrito; avaliação de comunicação à ANPD e aos titulares (LGPD) com o jurídico.

---

# Fase 3 — Caminhos de ataque

Achados isolados enganam: dois "Médios" encadeados podem dar controle total. Depois das Fases 1 e 2, monte o grafo.

- **AWS**: `pmapper graph create` e `pmapper analysis` (quem chega a administrador); `cloudsplaining download` + `cloudsplaining scan`; IAM Access Analyzer. Permissões que escalam privilégio: `iam:PassRole` com `lambda:CreateFunction`/`ec2:RunInstances`/`cloudformation:CreateStack`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`/`AttachRolePolicy`, `iam:PutUserPolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `lambda:UpdateFunctionCode`, `sts:AssumeRole` em `*`.
- **GCP**: `gcloud asset analyze-iam-policy --organization=<ORG> --permissions=iam.serviceAccounts.actAs` (repita para `iam.serviceAccounts.getAccessToken`, `iam.serviceAccountKeys.create`, `resourcemanager.projects.setIamPolicy`). Papéis que escalam: `serviceAccountTokenCreator`, `serviceAccountUser`, `serviceAccountKeyAdmin`, `editor`.
- **Active Directory**: caminhos até Domain Admins. Coleta do BloodHound só como **[B]**, combinada com o administrador do domínio (dispara alertas de EDR); sem ela, use o PingCastle e as consultas de 2.9.
- **Entre plataformas**: e-mail comprometido redefine senha de quê? Segredo do GitHub Actions dá que papel na nuvem? Role da instância exposta lê quais buckets e segredos? `service_role` do Supabase está em qual servidor? Token da Cloudflare altera DNS de quais domínios? SSO: uma conta do Entra abre quais consoles?

Entregue os 3 a 5 caminhos mais curtos até os ativos críticos (dados de clientes, dinheiro, administração de nuvem, domínio), cada um como: entrada, passos numerados com os IDs dos achados, impacto, técnicas MITRE ATT&CK e **a correção única que quebra a cadeia**. Achado que participa de um caminho sobe um nível de severidade.

# Fase 4 — Validação da detecção [B]

Controle ligado não prova que alguém é avisado. Com autorização, gere um evento controlado por plataforma e meça se e em quanto tempo o alerta chega a uma pessoa:

- AWS: `aws guardduty create-sample-findings --detector-id <id> --finding-types <tipo>` (achados marcados como amostra).
- Entra: login de teste com conta dedicada a partir de rede/país incomum.
- Honeytoken: uso da chave-isca.
- Servidor: login SSH/RDP falho repetido a partir de IP de teste.
- Cloudflare: requisições de teste que devem acionar WAF e rate limiting em homologação.

Registre por teste: evento, horário, alerta gerado (sim/não), quem recebeu, tempo até o aviso. Alerta que não chega a ninguém é achado Alto.

---

# Saída

## Achados em formato único

Grave `achados-AAAA-MM-DD.json` na pasta indicada pela pessoa, uma entrada por achado:

```json
{
  "id": "AWS-IAM-003",
  "impressao_digital": "sha256(check_id + ativo)",
  "fase": "comprometimento | postura | caminho | deteccao",
  "modulo": "aws",
  "check_id": "iam-usuario-sem-mfa",
  "ativo": "arn:aws:iam::123456789012:user/exemplo",
  "titulo": "Usuário com acesso ao console sem MFA",
  "severidade": "critico | alto | medio | baixo",
  "evidencia": "comando + trecho da saída, sem segredos",
  "risco": "o que um atacante consegue com isso",
  "correcao": "passo concreto",
  "esforco": "baixo | medio | alto",
  "referencias": {"cis": "1.10", "mitre": "T1078.004", "cve": null, "kev": false, "epss": null},
  "caminhos": ["CAMINHO-1"],
  "estado": "novo | pendente | resolvido | aceito",
  "primeira_vez": "AAAA-MM-DD"
}
```

## Baseline e diferença

No início, procure o `achados-*.json` mais recente na pasta. Compare pela impressão digital: **novo**, **pendente** (com idade em dias), **resolvido**. Leia também `excecoes.json`, se existir (riscos aceitos, com responsável e validade); exceção vencida volta a ser achado. Compare o inventário do Passo 0 com o anterior: ativo público novo é sempre destacado. Sem baseline, diga que esta é a primeira execução. A skill pode ser agendada (semanal: Fases 1 e 2 em Nível A; mensal: Fase 3).

## Relatório

### Layout e marca

O relatório é um documento Word (.docx), A4, margens de 2,5 cm, com a marca Carratu. Exporte também em PDF se a pessoa pedir.

- **Cabeçalho, em todas as páginas**: o logo `assets/logo-carratu.png` (na pasta desta skill), alinhado à esquerda, com cerca de 1,2 cm de altura e proporção original, seguido de uma linha fina cinza. Nada mais no cabeçalho.
- **Rodapé, em todas as páginas**: o texto exato `consultoria.carratu.com.br - Ubirajara Carratu`, centralizado, 8 pt, cinza escuro; à direita, "Página X de Y".
- **Capa**: logo maior (cerca de 4 cm de altura), título "Diagnóstico de Segurança", nome da empresa avaliada, data da execução e a marcação "Confidencial". A capa também leva o rodapé.
- **Estilo**: preto e tons de cinza, acompanhando o logo; fonte sem serifa; títulos de seção numerados conforme a ordem abaixo. Severidade sempre com cor e texto juntos (Crítico vermelho, Alto laranja, Médio amarelo, Baixo cinza), nunca só cor. Tabelas com cabeçalho repetido a cada página.
- Se o arquivo do logo não estiver disponível, peça-o à pessoa antes de gerar o documento. Não redesenhe o logo nem o substitua por texto estilizado; na falta dele, deixe o cabeçalho sem imagem e avise.

Conteúdo em português, nesta ordem:

1. **Resumo executivo**: veredito de comprometimento, número de achados por severidade, os 3 riscos mais urgentes.
2. **Avaliação de comprometimento**: veredito por plataforma, linha do tempo, indicadores, o que foi acessado, credenciais a rotacionar.
3. **Caminhos de ataque** e a correção que quebra cada um.
4. **Tabela de achados** por severidade (campos do JSON).
5. **Validação da detecção**, se executada.
6. **Cobertura**: cada módulo como Verificado, Parcial ou NÃO VERIFICADO, com o que faltou, e quais itens [B] ficaram sem autorização.
7. **Plano de ação**: 24 horas, 7 dias, 30 dias, 90 dias.
8. **Diferença para a execução anterior**.

## Severidade

- **Crítico**: indício de acesso indevido, ou explorável da internet agora (dados públicos, RDP/banco aberto, chave vazada válida, admin sem MFA, RLS ausente em dados sensíveis, CVE em KEV exposta).
- **Alto**: um passo de distância do comprometimento (escalada de privilégio, autenticação legada, origem fora da Cloudflare, sem logs, alerta que não chega).
- **Médio**: enfraquece a defesa (cabeçalhos, DMARC `p=none`, chaves antigas, sem rate limiting).
- **Baixo**: higiene.

Todo achado precisa de evidência observada nesta execução. Risco genérico não verificado vai para a cobertura, nunca para a tabela.

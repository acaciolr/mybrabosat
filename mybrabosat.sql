-- ============================================================================
--
--  ███╗   ███╗██╗   ██╗██████╗ ██████╗  █████╗ ██████╗  ██████╗ ███████╗ █████╗ ████████╗
--  ████╗ ████║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔══██╗╚══██╔══╝
--  ██╔████╔██║ ╚████╔╝ ██████╔╝██████╔╝███████║██████╔╝██║   ██║███████╗███████║   ██║
--  ██║╚██╔╝██║  ╚██╔╝  ██╔══██╗██╔══██╗██╔══██║██╔══██╗██║   ██║╚════██║██╔══██║   ██║
--  ██║ ╚═╝ ██║   ██║   ██████╔╝██║  ██║██║  ██║██████╔╝╚██████╔╝███████║██║  ██║   ██║
--  ╚═╝     ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝
--
--  MyBraboSat — MySQL Security Assessment, nivel enterprise
--  by • DBA BRABO                                  https://dbabrabo.com.br
-- ============================================================================
--
--  USO
--      HTML (padrao) — vira PDF pelo botao "Salvar em PDF" do proprio relatorio:
--      mysql --user=root -p --skip-column-names -f < mybrabosat.sql > MyBraboSat.html
--
--      TXT — para ler no terminal, por ssh, sem navegador:
--      mysql --user=root -p --skip-column-names -f \
--            --init-command="SET @mbs_formato='txt'" < mybrabosat.sql > MyBraboSat.txt
--
--      O HTML sai em UM arquivo so, com CSS embutido e sem dependencia
--      externa. O TXT tem os mesmos achados, a mesma nota e a mesma ordem,
--      em texto puro de ate 100 colunas.
--
--  REQUISITOS
--      MySQL 8.0 ou superior (testado em 8.0 e 8.4).
--      Conta com SELECT em mysql.*, performance_schema.* e information_schema.*,
--      mais CREATE TEMPORARY TABLES em sys. Em geral: root ou uma conta de
--      auditoria com GRANT SELECT, PROCESS ON *.* e CREATE TEMPORARY TABLES ON sys.*
--
--      Conta de auditoria dedicada, sem poder de escrita:
--          CREATE USER 'auditor'@'localhost' IDENTIFIED BY '<senha forte>';
--          GRANT SELECT, PROCESS ON *.* TO 'auditor'@'localhost';
--          GRANT CREATE TEMPORARY TABLES ON sys.* TO 'auditor'@'localhost';
--
--  O QUE MUDA EM RELACAO AO MySAT
--      1. Motor de achados. Cada verificacao grava numa tabela temporaria em
--         vez de imprimir HTML na hora. Dai saem o sumario executivo, a nota
--         de risco e a lista de falhas com remediacao — nenhum dos tres era
--         possivel no modelo antigo, que escrevia direto na saida.
--      2. Arquivo unico. O CSS vai embutido; nao existe mais mysat.css ao lado.
--      3. Remediacao. Toda falha traz o comando de correcao e o link para a
--         documentacao oficial do MySQL.
--      4. Atualizado. O MySAT 8.0 e de outubro de 2018. Aqui entram as
--         mudancas de ate 8.4: authentication_policy no lugar de
--         default_authentication_plugin, mysql_native_password desligado por
--         padrao, componentes de keyring e audit_log, FLUSH_PRIVILEGES
--         separado de RELOAD, partial_revokes, require_secure_transport.
--      5. Severidade e nota. Cada achado tem peso; o relatorio fecha com uma
--         nota de 0 a 100 e a contagem por severidade.
--
--  CREDITO
--      Inspirado no MySAT — MySQL Security Assessment Tool, de XeniaLAB srl
--      (meo@bogliolo.name), distribuido sob licenca MIT:
--      https://github.com/meob/MySAT
--
--      The MIT License (MIT) — Copyright (c) 2017-2018 XeniaLAB srl
--      Permission is hereby granted, free of charge, to any person obtaining a
--      copy of this software and associated documentation files (the
--      "Software"), to deal in the Software without restriction...
--
--  Este derivado: Copyright (c) 2026 DBA BRABO — tambem sob licenca MIT.
--
-- ============================================================================

-- O schema corrente precisa aceitar tabela temporaria; information_schema nao
-- aceita. Usamos sys apenas como namespace da temporaria da sessao — nada e
-- gravado em disco e nada do sys e tocado.
use sys;
set names utf8mb4;

set @mbs_versao     = '1.1.0';
set @mbs_gerado_em  = now();
set @mbs_servidor   = @@hostname;
set @mbs_versao_sql = version();
set @mbs_maior      = cast(substring_index(@@version,'.',1) as unsigned);
set @mbs_menor      = cast(substring_index(substring_index(@@version,'.',2),'.',-1) as unsigned);
set @mbs_e84        = (@mbs_maior > 8) or (@mbs_maior = 8 and @mbs_menor >= 4);
set @mbs_usuario    = current_user();
set @mbs_datadir    = @@datadir;

-- Formato da saida. Vem de fora, antes do script (--init-command ou um SET na
-- mesma sessao); sem nada, HTML. O script e uma sequencia de SELECTs soltos —
-- IF so existe dentro de procedure, e criar procedure exigiria escrita no
-- servidor —, entao cada SELECT de um formato carrega "where @mbs_html" ou
-- "where @mbs_txt" e sai vazio no outro.
set @mbs_formato    = lower(coalesce(@mbs_formato,'html'));
set @mbs_txt        = (@mbs_formato = 'txt');
set @mbs_html       = not @mbs_txt;

drop temporary table if exists mbs_achados;
create temporary table mbs_achados (
  ord       int unsigned not null auto_increment primary key,
  dominio   varchar(40)  not null,
  item      varchar(120) not null,
  sev       varchar(10)  not null,   -- critica | alta | media | baixa | info
  estado    varchar(10)  not null,   -- PASS | FAIL | AVALIAR | NA
  achado    text,
  correcao  text,
  doc       varchar(255),
  ref       varchar(120)
) engine=InnoDB;   -- MEMORY nao aceita coluna TEXT

-- ============================================================================
--  DOMINIO 1 — CONTAS E AUTENTICACAO
-- ============================================================================

-- 1.1 contas sem senha
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Conta sem senha definida','critica',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Nenhuma conta sem senha.',
          concat(count(*),' conta(s) sem senha: ',group_concat(concat(user,'@',host) separator ', '))),
       'ALTER USER ''<user>''@''<host>'' IDENTIFIED BY ''<senha forte>''; ou DROP USER se nao for usada.',
       'https://dev.mysql.com/doc/refman/8.0/en/assigning-passwords.html','CIS 1.3'
  from mysql.user
 where authentication_string = ''
   and plugin not in ('auth_socket','unix_socket','mysql_no_login');

-- 1.2 contas anonimas
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Conta anonima','critica',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Nenhuma conta anonima.',
          concat(count(*),' conta(s) anonima(s) em: ',group_concat(host separator ', '))),
       'DROP USER ''''@''<host>'';',
       'https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html','CIS 4.2'
  from mysql.user where user = '';

-- 1.3 conta administrativa acessivel de qualquer host
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Administrador acessivel de qualquer host','alta',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Nenhum administrador com host curinga.',
          concat(count(*),' conta(s) administrativa(s) com host ''%'': ',
                 group_concat(concat(user,'@',host) separator ', '))),
       'RENAME USER ''<user>''@''%'' TO ''<user>''@''<ip ou rede especifica>'';',
       'https://dev.mysql.com/doc/refman/8.0/en/account-names.html','CIS 1.5'
  from mysql.user where host in ('%','') and (Super_priv='Y' or user='root');

-- 1.4 root remoto
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','root acessivel remotamente','alta',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'root so acessa localmente.',
          concat('root existe em: ',group_concat(host separator ', '))),
       'DROP USER ''root''@''<host remoto>''; mantenha apenas ''root''@''localhost''.',
       'https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html','CIS 1.5'
  from mysql.user where user='root' and host not in ('localhost','127.0.0.1','::1');

-- 1.5 renomear a conta root
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Conta root com nome padrao','baixa',
       if(count(*)=0,'PASS','AVALIAR'),
       if(count(*)=0,'A conta root foi renomeada.','A conta administrativa ainda se chama root — alvo obvio de forca bruta.'),
       'RENAME USER ''root''@''localhost'' TO ''<nome nao obvio>''@''localhost'';',
       'https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html','Boa pratica'
  from mysql.user where user='root';

-- 1.6 plugin de autenticacao fraco
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Autenticacao com mysql_native_password','alta',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Nenhuma conta usa mysql_native_password.',
          concat(count(*),' conta(s) em mysql_native_password (SHA-1, sem salt por conexao; desligado por padrao no 8.4): ',
                 group_concat(concat(user,'@',host) separator ', '))),
       'ALTER USER ''<user>''@''<host>'' IDENTIFIED WITH caching_sha2_password BY ''<senha>'';',
       'https://dev.mysql.com/doc/refman/8.4/en/caching-sha2-pluggable-authentication.html','CIS 1.x'
  from mysql.user where plugin='mysql_native_password';

-- 1.7 politica de autenticacao
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','authentication_policy','media',
       if(variable_value like '%caching_sha2_password%','PASS','AVALIAR'),
       concat('authentication_policy = ',variable_value),
       'SET PERSIST authentication_policy = ''*,,''; -- primeiro fator obrigatorio = default_authentication_plugin forte',
       'https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_authentication_policy','MySQL 8.4'
  from performance_schema.global_variables where variable_name='authentication_policy';

-- 1.8 validate_password instalado
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Componente validate_password ativo','alta',
       if(count(*)>0,'PASS','FAIL'),
       if(count(*)>0,'validate_password esta carregado.','Nenhuma validacao de forca de senha no servidor.'),
       'INSTALL COMPONENT ''file://component_validate_password'';',
       'https://dev.mysql.com/doc/refman/8.0/en/validate-password.html','CIS 1.1'
  from performance_schema.global_variables
 where variable_name like 'validate_password%';

-- 1.9 tamanho minimo de senha
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Tamanho minimo de senha','media',
       if(cast(variable_value as unsigned)>=14,'PASS','FAIL'),
       concat('validate_password.length = ',variable_value,' (recomendado: >= 14)'),
       'SET PERSIST validate_password.length = 14;',
       'https://dev.mysql.com/doc/refman/8.0/en/validate-password-options-variables.html','CIS 1.1'
  from performance_schema.global_variables where variable_name='validate_password.length';

-- 1.10 politica de complexidade
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Complexidade de senha','media',
       if(upper(variable_value)='STRONG','PASS','AVALIAR'),
       concat('validate_password.policy = ',variable_value,' (recomendado: STRONG)'),
       'SET PERSIST validate_password.policy = ''STRONG'';',
       'https://dev.mysql.com/doc/refman/8.0/en/validate-password-options-variables.html','CIS 1.1'
  from performance_schema.global_variables where variable_name='validate_password.policy';

-- 1.11 expiracao de senha
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Expiracao de senha no servidor','media',
       if(cast(variable_value as unsigned) between 1 and 365,'PASS','AVALIAR'),
       concat('default_password_lifetime = ',variable_value,
              if(variable_value='0',' (0 = senha nunca expira)','')),
       'SET PERSIST default_password_lifetime = 180;',
       'https://dev.mysql.com/doc/refman/8.0/en/password-management.html','CIS 1.6'
  from performance_schema.global_variables where variable_name='default_password_lifetime';

-- 1.12 reuso de senha
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Historico de senhas (anti-reuso)','media',
       if(cast(variable_value as unsigned)>0,'PASS','FAIL'),
       concat('password_history = ',variable_value,' (0 = permite repetir a senha anterior)'),
       'SET PERSIST password_history = 6; SET PERSIST password_reuse_interval = 365;',
       'https://dev.mysql.com/doc/refman/8.0/en/password-management.html','CIS 1.7'
  from performance_schema.global_variables where variable_name='password_history';

-- 1.13 exigir senha atual na troca
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Exigir senha atual para troca','baixa',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('password_require_current = ',variable_value),
       'SET PERSIST password_require_current = ON;',
       'https://dev.mysql.com/doc/refman/8.0/en/password-management.html','Boa pratica'
  from performance_schema.global_variables where variable_name='password_require_current';

-- 1.14 bloqueio por tentativas
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Bloqueio por tentativas malsucedidas','media',
       if(count(*)>0,'PASS','FAIL'),
       if(count(*)>0,concat(count(*),' conta(s) com FAILED_LOGIN_ATTEMPTS configurado.'),
          'Nenhuma conta com bloqueio automatico apos erros de senha.'),
       'ALTER USER ''<user>''@''<host>'' FAILED_LOGIN_ATTEMPTS 5 PASSWORD_LOCK_TIME 1;',
       'https://dev.mysql.com/doc/refman/8.0/en/password-management.html#failed-login-tracking','Boa pratica'
  from mysql.user
 where User_attributes is not null
   and json_extract(User_attributes,'$.Password_locking.failed_login_attempts') is not null;

-- 1.15 contas bloqueadas / sem uso
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Contas de sistema devidamente travadas','info',
       'PASS',
       concat(count(*),' conta(s) com account_locked = Y (esperado para mysql.sys, mysql.session, mysql.infoschema).'),
       null,'https://dev.mysql.com/doc/refman/8.0/en/account-locking.html','Inventario'
  from mysql.user where account_locked='Y';

-- 1.16 uso de roles
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','Separacao por roles','media',
       if(count(*)>0,'PASS','AVALIAR'),
       if(count(*)>0,concat(count(*),' role(s) em uso.'),
          'Nenhuma role definida — privilegios provavelmente concedidos direto nas contas.'),
       'CREATE ROLE ''app_leitura''; GRANT SELECT ON app.* TO ''app_leitura''; GRANT ''app_leitura'' TO ''conta''@''host'';',
       'https://dev.mysql.com/doc/refman/8.0/en/roles.html','CIS 1.x'
  from mysql.role_edges;

-- 1.17 ativacao automatica de roles
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Contas e autenticacao','activate_all_roles_on_login','baixa',
       if(upper(variable_value)='OFF','PASS','AVALIAR'),
       concat('activate_all_roles_on_login = ',variable_value,
              if(upper(variable_value)='ON',' — toda role e ativada no login, o que anula a ideia de ativar so o necessario.','')),
       'SET PERSIST activate_all_roles_on_login = OFF;',
       'https://dev.mysql.com/doc/refman/8.0/en/roles.html','Boa pratica'
  from performance_schema.global_variables where variable_name='activate_all_roles_on_login';

-- ============================================================================
--  DOMINIO 2 — PRIVILEGIOS
-- ============================================================================

-- 2.1 privilegios globais amplos
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Privilegios','Contas com privilegio global perigoso','alta',
       if(count(*)=0,'PASS','AVALIAR'),
       if(count(*)=0,'Nenhuma conta nao-administrativa com privilegio global amplo.',
          concat(count(*),' conta(s) com SUPER/FILE/PROCESS/SHUTDOWN/GRANT global: ',
                 group_concat(distinct concat(grantee,' [',privilege_type,']') separator '; '))),
       'REVOKE <privilegio> ON *.* FROM ''<user>''@''<host>''; prefira privilegios dinamicos especificos (ex.: BINLOG_ADMIN, SYSTEM_VARIABLES_ADMIN).',
       'https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html','CIS 2.x'
  from information_schema.user_privileges
 where privilege_type in ('SUPER','FILE','PROCESS','SHUTDOWN','CREATE USER','RELOAD','GRANT OPTION')
   and grantee not like '''mysql.%';

-- 2.2 FILE
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Privilegios','Privilegio FILE concedido','alta',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Nenhuma conta com FILE.',
          concat('FILE concedido a: ',group_concat(distinct grantee separator ', '),
                 ' — permite ler e escrever arquivos no servidor.')),
       'REVOKE FILE ON *.* FROM ''<user>''@''<host>'';',
       'https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file','CIS 2.1'
  from information_schema.user_privileges
 where privilege_type='FILE' and grantee not like '''mysql.%';

-- 2.3 GRANT OPTION
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Privilegios','GRANT OPTION fora da administracao','alta',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Nenhuma conta comum pode repassar privilegio.',
          concat(count(*),' conta(s) com GRANT OPTION global: ',group_concat(distinct grantee separator ', '))),
       'REVOKE GRANT OPTION ON *.* FROM ''<user>''@''<host>'';',
       'https://dev.mysql.com/doc/refman/8.0/en/grant.html','CIS 2.x'
  from information_schema.user_privileges
 where privilege_type='GRANT OPTION' and grantee not like '''mysql.%' and grantee not like '''root%';

-- 2.4 escrita no dicionario
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Privilegios','Escrita nos schemas do sistema','critica',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Nenhuma conta comum escreve em mysql/sys.',
          concat(count(*),' concessao(oes) de escrita em schema do sistema: ',
                 group_concat(distinct concat(grantee,' -> ',table_schema) separator '; '))),
       'REVOKE INSERT,UPDATE,DELETE ON mysql.* FROM ''<user>''@''<host>'';',
       'https://dev.mysql.com/doc/refman/8.0/en/privilege-system.html','CIS 2.x'
  from information_schema.schema_privileges
 where table_schema in ('mysql','sys','performance_schema','information_schema')
   and privilege_type in ('INSERT','UPDATE','DELETE','DROP','ALTER','CREATE')
   and grantee not like '''mysql.%' and grantee not like '''root%';

-- 2.5 partial_revokes
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Privilegios','partial_revokes habilitado','baixa',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('partial_revokes = ',variable_value,
              ' — com ON da para conceder *.* e revogar schemas sensiveis especificos.'),
       'SET PERSIST partial_revokes = ON;',
       'https://dev.mysql.com/doc/refman/8.0/en/partial-revokes.html','Boa pratica'
  from performance_schema.global_variables where variable_name='partial_revokes';

-- 2.6 rotinas com SQL SECURITY DEFINER
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Privilegios','Rotinas com SQL SECURITY DEFINER','media',
       if(count(*)=0,'PASS','AVALIAR'),
       if(count(*)=0,'Nenhuma rotina DEFINER fora dos schemas do sistema.',
          concat(count(*),' rotina(s) executam com o privilegio do criador, nao do chamador.')),
       'ALTER PROCEDURE <nome> SQL SECURITY INVOKER; -- quando o chamador ja tiver o privilegio necessario',
       'https://dev.mysql.com/doc/refman/8.0/en/stored-objects-security.html','CIS 2.x'
  from information_schema.routines
 where security_type='DEFINER'
   and routine_schema not in ('mysql','sys','performance_schema','information_schema');

-- 2.7 views DEFINER
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Privilegios','Views com SQL SECURITY DEFINER','baixa',
       if(count(*)=0,'PASS','AVALIAR'),
       concat(count(*),' view(s) com DEFINER fora dos schemas do sistema.'),
       'ALTER VIEW <nome> SQL SECURITY INVOKER AS ...;',
       'https://dev.mysql.com/doc/refman/8.0/en/stored-objects-security.html','Boa pratica'
  from information_schema.views
 where security_type='DEFINER'
   and table_schema not in ('mysql','sys','performance_schema','information_schema');

-- 2.8 DEFINER orfao
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Privilegios','DEFINER apontando para conta inexistente','media',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Todo DEFINER aponta para uma conta que existe.',
          concat(count(*),' rotina(s) com DEFINER orfao — quebram na execucao e sinalizam conta removida sem limpeza.')),
       'Recrie o objeto com um DEFINER valido, ou recrie a conta.',
       'https://dev.mysql.com/doc/refman/8.0/en/stored-objects-security.html','Higiene'
  from information_schema.routines r
 where r.routine_schema not in ('mysql','sys','performance_schema','information_schema')
   and not exists (select 1 from mysql.user u
                    where concat(u.user,'@',u.host) = r.definer);

-- ============================================================================
--  DOMINIO 3 — REDE E CRIPTOGRAFIA
-- ============================================================================

-- 3.1 TLS disponivel
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','TLS configurado no servidor','critica',
       if(variable_value<>'','PASS','FAIL'),
       if(variable_value<>'',concat('Certificado em uso: ',variable_value),
          'Servidor sem certificado — trafego em texto claro.'),
       'Gere os certificados (mysql_ssl_rsa_setup ou a PKI da empresa) e aponte ssl_ca/ssl_cert/ssl_key no my.cnf.',
       'https://dev.mysql.com/doc/refman/8.0/en/using-encrypted-connections.html','CIS 6.x'
  from performance_schema.global_variables where variable_name='ssl_cert';

-- 3.2 exigir conexao segura
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','require_secure_transport','alta',
       if(upper(variable_value)='ON','PASS','FAIL'),
       concat('require_secure_transport = ',variable_value,
              if(upper(variable_value)<>'ON',' — conexao sem TLS continua sendo aceita.','')),
       'SET PERSIST require_secure_transport = ON;',
       'https://dev.mysql.com/doc/refman/8.0/en/using-encrypted-connections.html','CIS 6.x'
  from performance_schema.global_variables where variable_name='require_secure_transport';

-- 3.3 versoes de TLS
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','Versoes de TLS aceitas','alta',
       if(variable_value not like '%TLSv1,%' and variable_value not like '%TLSv1.1%'
          and variable_value not like 'TLSv1','PASS','FAIL'),
       concat('tls_version = ',variable_value,
              if(variable_value like '%TLSv1.1%' or variable_value like '%TLSv1,%',
                 ' — TLS 1.0/1.1 estao obsoletos e nao devem ser aceitos.','')),
       'SET PERSIST tls_version = ''TLSv1.2,TLSv1.3'';',
       'https://dev.mysql.com/doc/refman/8.0/en/encrypted-connection-protocols-ciphers.html','CIS 6.x'
  from performance_schema.global_variables where variable_name='tls_version';

-- 3.4 contas que exigem SSL
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','Contas sem exigencia de SSL','media',
       if(count(*)=0,'PASS','AVALIAR'),
       concat(count(*),' conta(s) sem REQUIRE SSL/X509 — dependem so do require_secure_transport global.'),
       'ALTER USER ''<user>''@''<host>'' REQUIRE SSL; -- ou REQUIRE X509 para exigir certificado de cliente',
       'https://dev.mysql.com/doc/refman/8.0/en/create-user.html#create-user-tls','CIS 6.x'
  from mysql.user
 where ssl_type='' and account_locked='N' and user not like 'mysql.%';

-- 3.5 validacao de certificado
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','Validacao de certificado no startup','baixa',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('tls_certificates_enforced_validation = ',variable_value,
              ' — com ON o servidor recusa subir com certificado invalido em vez de seguir sem TLS.'),
       'SET PERSIST tls_certificates_enforced_validation = ON;',
       'https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html','MySQL 8.4'
  from performance_schema.global_variables where variable_name='tls_certificates_enforced_validation';

-- 3.6 criptografia de tablespace
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','Criptografia em repouso (tablespace)','alta',
       if(count(*)>0,'PASS','FAIL'),
       if(count(*)>0,concat(count(*),' tabela(s) com ENCRYPTION=''Y''.'),
          'Nenhuma tabela cifrada em repouso.'),
       'ALTER TABLE <schema>.<tabela> ENCRYPTION=''Y''; -- exige componente de keyring carregado',
       'https://dev.mysql.com/doc/refman/8.0/en/innodb-data-encryption.html','CIS 7.x'
  from information_schema.tables where create_options like '%ENCRYPTION="Y"%';

-- 3.7 keyring
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','Componente de keyring ativo','alta',
       if(count(*)>0,'PASS','FAIL'),
       if(count(*)>0,'Keyring carregado — base para criptografia em repouso.',
          'Nenhum keyring. Sem ele nao ha criptografia de tablespace, redo nem binlog.'),
       'Configure component_keyring_file (ou o keyring corporativo) em mysqld.my e carregue com INSTALL COMPONENT.',
       'https://dev.mysql.com/doc/refman/8.0/en/keyring-component-installation.html','CIS 7.x'
  from performance_schema.keyring_component_status;

-- 3.8 redo e undo cifrados
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','Redo log cifrado','media',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('innodb_redo_log_encrypt = ',variable_value),
       'SET PERSIST innodb_redo_log_encrypt = ON;',
       'https://dev.mysql.com/doc/refman/8.0/en/innodb-data-encryption.html','CIS 7.x'
  from performance_schema.global_variables where variable_name='innodb_redo_log_encrypt';

insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','Undo log cifrado','media',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('innodb_undo_log_encrypt = ',variable_value),
       'SET PERSIST innodb_undo_log_encrypt = ON;',
       'https://dev.mysql.com/doc/refman/8.0/en/innodb-data-encryption.html','CIS 7.x'
  from performance_schema.global_variables where variable_name='innodb_undo_log_encrypt';

-- 3.9 binlog cifrado
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Rede e criptografia','Binary log cifrado','media',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('binlog_encryption = ',variable_value,
              ' — o binlog carrega os dados alterados em claro quando desligado.'),
       'SET PERSIST binlog_encryption = ON;',
       'https://dev.mysql.com/doc/refman/8.0/en/replication-binlog-encryption.html','CIS 7.x'
  from performance_schema.global_variables where variable_name='binlog_encryption';

-- ============================================================================
--  DOMINIO 4 — CONFIGURACAO SEGURA
-- ============================================================================

-- 4.1 local_infile
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','local_infile desligado','alta',
       if(upper(variable_value)='OFF','PASS','FAIL'),
       concat('local_infile = ',variable_value,
              if(upper(variable_value)='ON',' — vetor de leitura de arquivo do cliente por servidor malicioso.','')),
       'SET PERSIST local_infile = OFF;',
       'https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html','CIS 4.3'
  from performance_schema.global_variables where variable_name='local_infile';

-- 4.2 secure_file_priv
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','secure_file_priv restrito','alta',
       if(variable_value<>'' ,'PASS','FAIL'),
       concat('secure_file_priv = ''',variable_value,'''',
              if(variable_value='',' — import/export sem restricao de diretorio.','')),
       'Defina secure_file_priv = /var/lib/mysql-files no my.cnf (exige restart), ou NULL para desabilitar de vez.',
       'https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_secure_file_priv','CIS 4.4'
  from performance_schema.global_variables where variable_name='secure_file_priv';

-- 4.3 symbolic links
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','Symbolic links desabilitados','media',
       if(upper(variable_value) in ('OFF','DISABLED'),'PASS','FAIL'),
       concat('have_symlink = ',variable_value),
       'Adicione skip-symbolic-links no my.cnf e reinicie.',
       'https://dev.mysql.com/doc/refman/8.0/en/symbolic-links-to-tables.html','CIS 4.5'
  from performance_schema.global_variables where variable_name='have_symlink';

-- 4.4 skip_name_resolve
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','skip_name_resolve','baixa',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('skip_name_resolve = ',variable_value,
              ' — com OFF o controle de acesso depende de DNS, que pode ser envenenado.'),
       'Adicione skip-name-resolve no my.cnf e troque hosts por IP/rede nas contas.',
       'https://dev.mysql.com/doc/refman/8.0/en/host-cache.html','CIS 4.x'
  from performance_schema.global_variables where variable_name='skip_name_resolve';

-- 4.5 protocolo X
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','Plugin X Protocol (mysqlx)','baixa',
       if(count(*)=0,'PASS','AVALIAR'),
       if(count(*)=0,'X Protocol nao esta ativo.',
          'X Protocol ativo na porta 33060 — desligue se a aplicacao nao usa Document Store.'),
       'Adicione mysqlx=0 no my.cnf, ou UNINSTALL PLUGIN mysqlx;',
       'https://dev.mysql.com/doc/refman/8.0/en/x-plugin.html','Superficie de ataque'
  from information_schema.plugins where plugin_name='mysqlx' and plugin_status='ACTIVE';

-- 4.6 version comment exposto
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','Banner de versao exposto','baixa',
       'AVALIAR',
       concat('version = ',@@version,' / version_comment = ',@@version_comment,
              ' — a versao exata aparece no handshake, antes de qualquer autenticacao.'),
       'SET PERSIST version_comment = ''''; -- nao esconde a versao, mas reduz a informacao oferecida',
       'https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html','Boa pratica'
  from dual;

-- 4.7 sql_mode
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','sql_mode com STRICT','media',
       if(variable_value like '%STRICT_%','PASS','FAIL'),
       concat('sql_mode = ',variable_value,
              if(variable_value not like '%STRICT_%',' — sem STRICT o servidor aceita dado truncado em silencio.','')),
       'SET PERSIST sql_mode = ''ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'';',
       'https://dev.mysql.com/doc/refman/8.0/en/sql-mode.html','Integridade'
  from performance_schema.global_variables where variable_name='sql_mode';

-- 4.8 automatic_sp_privileges
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','automatic_sp_privileges','baixa',
       if(upper(variable_value)='OFF','PASS','AVALIAR'),
       concat('automatic_sp_privileges = ',variable_value,
              ' — com ON quem cria rotina ganha EXECUTE e ALTER ROUTINE automaticamente.'),
       'SET PERSIST automatic_sp_privileges = OFF;',
       'https://dev.mysql.com/doc/refman/8.0/en/stored-routines-privileges.html','CIS 4.x'
  from performance_schema.global_variables where variable_name='automatic_sp_privileges';

-- 4.9 schema de teste
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','Schema de teste presente','media',
       if(count(*)=0,'PASS','FAIL'),
       if(count(*)=0,'Nenhum schema de teste.',
          concat('Schema(s) encontrado(s): ',group_concat(schema_name separator ', '))),
       'DROP DATABASE test;',
       'https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html','CIS 4.1'
  from information_schema.schemata where schema_name in ('test','demo','sample');

-- 4.10 dados fora do InnoDB
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Configuracao segura','Tabelas fora do InnoDB','media',
       if(count(*)=0,'PASS','AVALIAR'),
       if(count(*)=0,'Todas as tabelas de aplicacao usam InnoDB.',
          concat(count(*),' tabela(s) em MyISAM/MEMORY/outro — sem transacao, sem crash recovery e sem criptografia em repouso.')),
       'ALTER TABLE <schema>.<tabela> ENGINE=InnoDB;',
       'https://dev.mysql.com/doc/refman/8.0/en/innodb-introduction.html','CIS 4.x'
  from information_schema.tables
 where table_schema not in ('mysql','sys','performance_schema','information_schema')
   and table_type='BASE TABLE' and engine <> 'InnoDB';

-- ============================================================================
--  DOMINIO 5 — LOG E AUDITORIA
-- ============================================================================

-- 5.1 error log
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Log e auditoria','Error log em arquivo','media',
       if(variable_value<>'' and lower(variable_value)<>'stderr','PASS','AVALIAR'),
       concat('log_error = ',if(variable_value='','(stderr)',variable_value)),
       'SET PERSIST log_error = ''/var/log/mysql/error.log'';',
       'https://dev.mysql.com/doc/refman/8.0/en/error-log.html','CIS 5.1'
  from performance_schema.global_variables where variable_name='log_error';

-- 5.2 verbosidade do error log
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Log e auditoria','Verbosidade do error log','baixa',
       if(cast(variable_value as unsigned)>=2,'PASS','AVALIAR'),
       concat('log_error_verbosity = ',variable_value,' (1=erro, 2=erro+warning, 3=+nota)'),
       'SET PERSIST log_error_verbosity = 2;',
       'https://dev.mysql.com/doc/refman/8.0/en/error-log-verbosity.html','CIS 5.x'
  from performance_schema.global_variables where variable_name='log_error_verbosity';

-- 5.3 plugin/componente de auditoria
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Log e auditoria','Auditoria instalada','alta',
       if(count(*)>0,'PASS','FAIL'),
       if(count(*)>0,concat('Auditoria ativa: ',group_concat(plugin_name separator ', ')),
          'Nenhum plugin de auditoria. Sem isso nao ha trilha de quem acessou o que.'),
       'Enterprise: INSTALL COMPONENT ''file://component_audit_log''. Community: use audit_log do Percona Server ou server_audit do MariaDB/Percona.',
       'https://dev.mysql.com/doc/refman/8.0/en/audit-log.html','CIS 5.x'
  from information_schema.plugins
 where plugin_name in ('audit_log','server_audit','AUDIT_LOG') and plugin_status='ACTIVE';

-- 5.4 general log (nao deve ficar ligado)
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Log e auditoria','General log desligado','media',
       if(upper(variable_value)='OFF','PASS','FAIL'),
       concat('general_log = ',variable_value,
              if(upper(variable_value)='ON',' — grava toda query, inclusive senhas em texto claro, e pesa no disco.','')),
       'SET PERSIST general_log = OFF; -- use auditoria de verdade, nao o general log',
       'https://dev.mysql.com/doc/refman/8.0/en/query-log.html','CIS 5.2'
  from performance_schema.global_variables where variable_name='general_log';

-- 5.5 slow query log
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Log e auditoria','Slow query log ativo','baixa',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('slow_query_log = ',variable_value),
       'SET PERSIST slow_query_log = ON; SET PERSIST long_query_time = 1;',
       'https://dev.mysql.com/doc/refman/8.0/en/slow-query-log.html','Operacao'
  from performance_schema.global_variables where variable_name='slow_query_log';

-- 5.6 binlog ligado
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Log e auditoria','Binary log habilitado','alta',
       if(upper(variable_value)='ON','PASS','FAIL'),
       concat('log_bin = ',variable_value,
              if(upper(variable_value)<>'ON',' — sem binlog nao existe PITR nem replicacao.','')),
       'Habilite log_bin no my.cnf (padrao a partir do 8.0) e defina binlog_expire_logs_seconds.',
       'https://dev.mysql.com/doc/refman/8.0/en/binary-log.html','RPO'
  from performance_schema.global_variables where variable_name='log_bin';

-- 5.7 retencao do binlog
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Log e auditoria','Retencao do binary log','media',
       if(cast(variable_value as unsigned) between 86400 and 2592000,'PASS','AVALIAR'),
       concat('binlog_expire_logs_seconds = ',variable_value,' (',round(variable_value/86400,1),' dia(s))'),
       'SET PERSIST binlog_expire_logs_seconds = 604800; -- 7 dias, ajuste ao seu RPO',
       'https://dev.mysql.com/doc/refman/8.0/en/replication-options-binary-log.html','RPO'
  from performance_schema.global_variables where variable_name='binlog_expire_logs_seconds';

-- 5.8 performance_schema
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Log e auditoria','performance_schema habilitado','baixa',
       if(upper(variable_value)='ON','PASS','AVALIAR'),
       concat('performance_schema = ',variable_value,' — base de qualquer diagnostico e da propria auditoria de acesso.'),
       'Habilite performance_schema = ON no my.cnf.',
       'https://dev.mysql.com/doc/refman/8.0/en/performance-schema.html','Operacao'
  from performance_schema.global_variables where variable_name='performance_schema';

-- ============================================================================
--  DOMINIO 6 — DADOS SENSIVEIS E LGPD
-- ============================================================================

-- 6.1 colunas com cara de dado pessoal
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Dados sensiveis','Colunas candidatas a dado pessoal','media',
       if(count(*)=0,'PASS','AVALIAR'),
       if(count(*)=0,'Nenhuma coluna com nome tipico de dado pessoal.',
          concat(count(*),' coluna(s) com nome sugestivo de dado pessoal. Classifique e decida mascaramento, cifra ou minimizacao.')),
       'Classifique os dados; avalie cifra em coluna, mascaramento na view ou component_masking.',
       'https://dev.mysql.com/doc/refman/8.0/en/data-masking.html','LGPD art. 46'
  from information_schema.columns
 where table_schema not in ('mysql','sys','performance_schema','information_schema')
   and (column_name regexp '(cpf|cnpj|rg|passaport|nome|email|e_mail|mail|telefone|phone|celular|endereco|address|cep|zip|nasc|birth|cartao|card|salario|salary|senha|password|token|secret)');

-- 6.2 colunas com nome de segredo em texto claro
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Dados sensiveis','Possivel segredo em coluna de texto','alta',
       if(count(*)=0,'PASS','AVALIAR'),
       if(count(*)=0,'Nenhuma coluna de senha/token em tipo de texto simples.',
          concat(count(*),' coluna(s) chamadas senha/password/token/secret em tipo texto — confirme se guardam hash, nunca o valor.')),
       'Guarde hash com algoritmo lento e com sal (bcrypt/argon2 na aplicacao). Nunca MD5/SHA1, nunca texto claro.',
       'https://dev.mysql.com/doc/refman/8.0/en/encryption-functions.html','LGPD art. 46'
  from information_schema.columns
 where table_schema not in ('mysql','sys','performance_schema','information_schema')
   and column_name regexp '(senha|password|passwd|token|secret|api_?key)'
   and data_type in ('char','varchar','text','tinytext','mediumtext','longtext');

-- 6.3 tabelas sem chave primaria
insert into mbs_achados (dominio,item,sev,estado,achado,correcao,doc,ref)
select 'Dados sensiveis','Tabelas sem chave primaria','baixa',
       if(count(*)=0,'PASS','AVALIAR'),
       concat(count(*),' tabela(s) sem PK — atrapalham replicacao por linha, PITR e rastreio de alteracao.'),
       'ALTER TABLE <schema>.<tabela> ADD PRIMARY KEY (<coluna>);',
       'https://dev.mysql.com/doc/refman/8.0/en/replication-features-differing-tables.html','Rastreabilidade'
  from information_schema.tables t
 where t.table_schema not in ('mysql','sys','performance_schema','information_schema')
   and t.table_type='BASE TABLE'
   and not exists (select 1 from information_schema.table_constraints c
                    where c.table_schema=t.table_schema and c.table_name=t.table_name
                      and c.constraint_type='PRIMARY KEY');

-- ============================================================================
--  NOTA DE RISCO
--  Peso por severidade; FAIL perde o peso inteiro, AVALIAR perde metade.
-- ============================================================================

set @peso_total = (select ifnull(sum(case sev when 'critica' then 10 when 'alta' then 6
                                              when 'media' then 3 when 'baixa' then 1 else 0 end),0)
                     from mbs_achados where estado in ('PASS','FAIL','AVALIAR'));
set @peso_perdido = (select ifnull(sum(case sev when 'critica' then 10 when 'alta' then 6
                                                when 'media' then 3 when 'baixa' then 1 else 0 end
                                       * case estado when 'FAIL' then 1 when 'AVALIAR' then 0.5 else 0 end),0)
                       from mbs_achados);
set @nota = if(@peso_total=0,100,round(100*(1-(@peso_perdido/@peso_total))));
set @n_crit  = (select count(*) from mbs_achados where estado='FAIL' and sev='critica');
set @n_alta  = (select count(*) from mbs_achados where estado='FAIL' and sev='alta');
set @n_media = (select count(*) from mbs_achados where estado='FAIL' and sev='media');
set @n_baixa = (select count(*) from mbs_achados where estado='FAIL' and sev='baixa');
set @n_aval  = (select count(*) from mbs_achados where estado='AVALIAR');
set @n_pass  = (select count(*) from mbs_achados where estado='PASS');
set @n_tot   = (select count(*) from mbs_achados where estado in ('PASS','FAIL','AVALIAR'));
set @classe  = if(@nota>=90,'bom',if(@nota>=70,'medio',if(@nota>=50,'ruim','critico')));
set @veredito = case
  when @n_crit>0 then 'Ha falha critica aberta. Trate antes de qualquer outra coisa.'
  when @nota>=90 then 'Postura solida. O que sobrou e refinamento.'
  when @nota>=70 then 'Base razoavel, com lacunas que valem um plano de correcao.'
  when @nota>=50 then 'Varias frentes abertas. Priorize as de severidade alta.'
  else 'Postura fragil. Recomenda-se plano de remediacao imediato.' end;

-- ============================================================================
--  RELATORIO — arquivo unico, CSS embutido
-- ============================================================================

select '<!DOCTYPE html>' from dual where @mbs_html;
select '<html lang="pt-BR"><head><meta charset="utf-8">' from dual where @mbs_html;
select '<meta name="viewport" content="width=device-width, initial-scale=1">' from dual where @mbs_html;
select concat('<title>MyBraboSat — ',@mbs_servidor,'</title>') from dual where @mbs_html;
select '<style>' from dual where @mbs_html;
select ':root{--bg:#0B0E14;--bg2:#11151D;--bg3:#171C26;--fg:#EDF2F7;--fg1:#A8B6C6;--fg2:#6D7E90;' from dual where @mbs_html;
select '--line:#202836;--brand:#FF8A4C;--ok:#4ADE80;--warn:#E8B33C;--err:#F0705A;--info:#4B93FF;--crit:#D7263D}' from dual where @mbs_html;
select '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg1);' from dual where @mbs_html;
select 'font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:0 0 60px}' from dual where @mbs_html;
select '.wrap{max-width:1180px;margin:0 auto;padding:0 24px}' from dual where @mbs_html;
select 'header{background:linear-gradient(135deg,#1A1008 0%,var(--bg) 55%);border-bottom:1px solid var(--line);padding:40px 0 32px;margin-bottom:32px}' from dual where @mbs_html;
select 'h1{margin:0;font-size:30px;color:var(--fg);letter-spacing:-.02em}h1 b{color:var(--brand)}' from dual where @mbs_html;
select 'h2{margin:40px 0 14px;font-size:20px;color:var(--fg);border-bottom:1px solid var(--line);padding-bottom:8px}' from dual where @mbs_html;
select 'h3{margin:26px 0 10px;font-size:16px;color:var(--fg)}' from dual where @mbs_html;
select '.sub{color:var(--fg2);font-size:13px;margin-top:6px}' from dual where @mbs_html;
select '.conf{display:inline-block;margin-top:14px;padding:4px 12px;border:1px solid var(--err);color:var(--err);' from dual where @mbs_html;
select 'border-radius:999px;font-size:11px;letter-spacing:.14em;text-transform:uppercase}' from dual where @mbs_html;
select '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:22px 0}' from dual where @mbs_html;
select '.card{background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:16px}' from dual where @mbs_html;
select '.card .n{font-size:30px;font-weight:700;line-height:1.1;color:var(--fg)}' from dual where @mbs_html;
select '.card .l{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--fg2);margin-top:4px}' from dual where @mbs_html;
select '.nota{display:flex;align-items:center;gap:22px;background:var(--bg2);border:1px solid var(--line);' from dual where @mbs_html;
select 'border-radius:14px;padding:22px;margin:22px 0}' from dual where @mbs_html;
select '.nota .v{font-size:58px;font-weight:800;line-height:1}' from dual where @mbs_html;
select '.bom .v{color:var(--ok)}.medio .v{color:var(--warn)}.ruim .v{color:var(--err)}.critico .v{color:var(--crit)}' from dual where @mbs_html;
select 'table{width:100%;border-collapse:collapse;margin:14px 0;font-size:13.5px}' from dual where @mbs_html;
select 'th{text-align:left;background:var(--bg3);color:var(--fg2);font-weight:600;font-size:11px;' from dual where @mbs_html;
select 'letter-spacing:.1em;text-transform:uppercase;padding:9px 12px;border-bottom:1px solid var(--line)}' from dual where @mbs_html;
select 'td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}' from dual where @mbs_html;
select 'tr:hover td{background:var(--bg2)}' from dual where @mbs_html;
select '.sev{display:inline-block;padding:2px 9px;border-radius:999px;font-size:10.5px;font-weight:700;' from dual where @mbs_html;
select 'letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}' from dual where @mbs_html;
select '.s-critica{background:rgba(215,38,61,.18);color:#FF8597}.s-alta{background:rgba(240,112,90,.16);color:var(--err)}' from dual where @mbs_html;
select '.s-media{background:rgba(232,179,60,.14);color:var(--warn)}.s-baixa{background:rgba(75,147,255,.14);color:#8FBCFF}' from dual where @mbs_html;
select '.s-info{background:rgba(109,126,144,.16);color:var(--fg2)}' from dual where @mbs_html;
select '.e-PASS{color:var(--ok);font-weight:700}.e-FAIL{color:var(--err);font-weight:700}' from dual where @mbs_html;
select '.e-AVALIAR{color:var(--warn);font-weight:700}.e-NA{color:var(--fg2)}' from dual where @mbs_html;
select 'code{background:var(--bg3);border:1px solid var(--line);border-radius:5px;padding:1px 6px;' from dual where @mbs_html;
select 'font:12.5px/1.5 ui-monospace,Consolas,monospace;color:#FFD2B8;white-space:pre-wrap;display:inline-block;max-width:100%}' from dual where @mbs_html;
select 'a{color:var(--brand)}a:hover{color:#FFB48A}' from dual where @mbs_html;
select '.vazio{color:var(--ok);background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:18px}' from dual where @mbs_html;
select 'footer{margin-top:50px;padding-top:20px;border-top:1px solid var(--line);color:var(--fg2);font-size:12px}' from dual where @mbs_html;
select '.acoes{position:fixed;bottom:20px;right:20px;z-index:50;display:flex;gap:8px}' from dual where @mbs_html;
select '.acoes .btn{box-shadow:0 6px 20px rgba(0,0,0,.45)}' from dual where @mbs_html;
select '.btn{background:var(--brand);color:#1A0F07;border:0;border-radius:9px;padding:9px 16px;' from dual where @mbs_html;
select 'font:600 13px/1 inherit;cursor:pointer;box-shadow:0 6px 18px -6px rgba(0,0,0,.7)}' from dual where @mbs_html;
select '.btn:hover{background:#FFB48A}.btn--g{background:var(--bg3);color:var(--fg1);border:1px solid var(--line)}' from dual where @mbs_html;
select '.toc{background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:4px 0 8px}' from dual where @mbs_html;
select '.toc .t{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--fg2);margin-bottom:10px}' from dual where @mbs_html;
select '.toc ol{margin:0;padding-left:20px;columns:2;column-gap:32px}' from dual where @mbs_html;
select '.toc li{margin:4px 0;break-inside:avoid}.toc a{text-decoration:none}.toc a:hover{text-decoration:underline}' from dual where @mbs_html;
select '.toc .c{color:var(--fg2);font-size:12px}' from dual where @mbs_html;
select '.topo-link{float:right;font-size:11px;font-weight:400;color:var(--fg2);text-decoration:none}' from dual where @mbs_html;
select '.topo-link:hover{color:var(--brand)}' from dual where @mbs_html;
select '.capa{min-height:72vh;display:flex;flex-direction:column;justify-content:center;' from dual where @mbs_html;
select 'border-bottom:1px solid var(--line);padding:60px 0 50px;margin-bottom:34px}' from dual where @mbs_html;
select '.capa .marca{font-size:12px;letter-spacing:.3em;text-transform:uppercase;color:var(--brand);margin-bottom:26px}' from dual where @mbs_html;
select '.capa h1{font-size:44px;line-height:1.05;margin:0 0 10px}' from dual where @mbs_html;
select '.capa .tipo{font-size:19px;color:var(--fg1);margin-bottom:34px}' from dual where @mbs_html;
select '.capa .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px;' from dual where @mbs_html;
select 'border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:20px 0;margin-bottom:26px}' from dual where @mbs_html;
select '.capa .meta .k{font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--fg2)}' from dual where @mbs_html;
select '.capa .meta .v{color:var(--fg);margin-top:3px;font-weight:600}' from dual where @mbs_html;
select '.capa .rod{color:var(--fg2);font-size:12.5px;line-height:1.7}' from dual where @mbs_html;
select '.leg{color:var(--fg1);margin:0 0 16px;max-width:76ch}' from dual where @mbs_html;
select '.nota-rodape{color:var(--fg2);font-size:12px;font-style:italic;margin:10px 0 0}' from dual where @mbs_html;
select '.doc-rodape{display:none}' from dual where @mbs_html;
select '@media print{' from dual where @mbs_html;
select '  :root{--bg:#fff;--bg2:#fff;--bg3:#f4f6f8;--fg:#000;--fg1:#222;--fg2:#555;--line:#ccc;--brand:#C2410C}' from dual where @mbs_html;
select '  body{background:#fff;color:#000;font-size:11pt}' from dual where @mbs_html;
select '  header{background:#fff;border-bottom:2px solid #000;padding:0 0 12px;margin-bottom:18px}' from dual where @mbs_html;
select '  h1{font-size:20pt}h2{font-size:13pt;page-break-after:avoid}h3{page-break-after:avoid}' from dual where @mbs_html;
select '  .acoes{display:none}.topo-link{display:none}' from dual where @mbs_html;
select '  .card,.nota{border:1px solid #bbb}' from dual where @mbs_html;
select '  table{font-size:9pt}th{background:#eee;color:#000}' from dual where @mbs_html;
select '  tr,.card,.nota,h2,h3{break-inside:avoid;page-break-inside:avoid}' from dual where @mbs_html;
select '  code{background:#f4f6f8;color:#111;border:1px solid #ddd}' from dual where @mbs_html;
select '  a{color:#000;text-decoration:underline}  /* o PDF do navegador mantem o link clicavel */' from dual where @mbs_html;
select '  .capa{min-height:0;height:auto;padding:0 0 30px;page-break-after:always;border:0}' from dual where @mbs_html;
select '  .leg{max-width:none;text-align:justify}' from dual where @mbs_html;
select '  .toc ol{columns:1}' from dual where @mbs_html;
select '  .capa h1{font-size:30pt}.capa .tipo{font-size:13pt}' from dual where @mbs_html;
select '  .toc{page-break-after:always;border:0;padding:0}' from dual where @mbs_html;
select '  .doc-rodape{display:block;position:fixed;bottom:0;left:0;right:0;font-size:8pt;color:#555;' from dual where @mbs_html;
select '    border-top:1px solid #ccc;padding:4px 0;background:#fff}' from dual where @mbs_html;
select '  body{padding-bottom:22mm}' from dual where @mbs_html;
select '  .secao{page-break-before:always}' from dual where @mbs_html;
select '  .sev{border:1px solid #999;color:#000 !important;background:#fff !important}' from dual where @mbs_html;
select '  .e-PASS,.e-FAIL,.e-AVALIAR{color:#000 !important}' from dual where @mbs_html;
select '}' from dual where @mbs_html;
select '</style></head><body>' from dual where @mbs_html;

-- ---------------------------------------------------------------- capa
select '<div class="wrap"><section class="capa">' from dual where @mbs_html;
select '<div class="marca">DBA BRABO</div>' from dual where @mbs_html;
select '<h1>Avaliacao de Seguranca<br>do Banco de Dados <b>MySQL</b></h1>' from dual where @mbs_html;
select '<div class="tipo">Relatorio tecnico de assessment &mdash; gerado pelo MyBraboSat</div>' from dual where @mbs_html;
select '<div class="meta">' from dual where @mbs_html;
select concat('<div><div class="k">Servidor</div><div class="v">',@mbs_servidor,'</div></div>') from dual where @mbs_html;
select concat('<div><div class="k">Versao do MySQL</div><div class="v">',@mbs_versao_sql,'</div></div>') from dual where @mbs_html;
select concat('<div><div class="k">Data da coleta</div><div class="v">',
              date_format(@mbs_gerado_em,'%d/%m/%Y %H:%i'),'</div></div>') from dual where @mbs_html;
select concat('<div><div class="k">Nota de postura</div><div class="v">',@nota,'/100</div></div>') from dual where @mbs_html;
select '</div>' from dual where @mbs_html;
select concat('<div class="rod">Coleta executada por <b>',@mbs_usuario,'</b>. ',
              'Este documento retrata a configuracao do servidor no instante da coleta.<br>',
              'Ferramenta: MyBraboSat ',@mbs_versao,' &mdash; by &bull; DBA BRABO.</div>') from dual where @mbs_html;
select '<div class="conf">Altamente confidencial &mdash; distribuicao restrita</div>' from dual where @mbs_html;
select '</section></div>' from dual where @mbs_html;

-- rodape que se repete em toda pagina impressa
select concat('<div class="doc-rodape"><div class="wrap">Avaliacao de Seguranca MySQL &middot; ',
              @mbs_servidor,' &middot; ',date_format(@mbs_gerado_em,'%d/%m/%Y'),
              ' &middot; Altamente confidencial &middot; MyBraboSat by DBA BRABO</div></div>') from dual where @mbs_html;
select '<div class="acoes">' from dual where @mbs_html;
select '<button class="btn" onclick="window.print()" title="Abre a caixa de impressao; escolha Salvar como PDF">Salvar em PDF</button>' from dual where @mbs_html;
select '<button class="btn btn--g" onclick="document.querySelectorAll(''details'').forEach(d=>d.open=true);window.print()" style="display:none"></button>' from dual where @mbs_html;
select '</div>' from dual where @mbs_html;
select '<div class="wrap">' from dual where @mbs_html;

select '<div class="toc" id="indice"><div class="t">Indice</div><ol>' from dual where @mbs_html;
select '<li><a href="#documento">Sobre este documento</a> <span class="c">&mdash; escopo e metodo</span></li>' from dual where @mbs_html;
select '<li><a href="#legenda">Como ler o relatorio</a> <span class="c">&mdash; severidades e estados</span></li>' from dual where @mbs_html;
select '<li><a href="#contexto">Seguranca em MySQL</a> <span class="c">&mdash; por que isto importa</span></li>' from dual where @mbs_html;
select concat('<li><a href="#sumario">Sumario executivo</a> <span class="c">&mdash; nota ',@nota,'/100</span></li>') from dual where @mbs_html;
select concat('<li><a href="#falhas">Falhas e remediacao</a> <span class="c">&mdash; ',
              @n_crit+@n_alta+@n_media+@n_baixa,' item(ns)</span></li>') from dual where @mbs_html;
select concat('<li><a href="#avaliar">Itens para avaliar</a> <span class="c">&mdash; ',@n_aval,' item(ns)</span></li>') from dual where @mbs_html;
select concat('<li><a href="#todas">Todas as verificacoes</a> <span class="c">&mdash; ',@n_tot,' checks</span></li>') from dual where @mbs_html;
select '<li><a href="#inventario">Inventario do servidor</a> <span class="c">&mdash; contexto tecnico</span></li>' from dual where @mbs_html;
select '<li><a href="#limites">Limitacoes e proximos passos</a></li>' from dual where @mbs_html;
select '<li><a href="#referencias">Referencias</a></li>' from dual where @mbs_html;
select '</ol></div>' from dual where @mbs_html;

-- ======================================================= sobre o documento
select '<h2 class="secao" id="documento">1. Sobre este documento<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">Este relatorio e o resultado de uma coleta automatizada de configuracao em um servidor MySQL. Ele nao substitui um teste de intrusao nem uma revisao de codigo da aplicacao: olha para como o banco esta configurado, quem tem acesso a ele e o que o servidor registra sobre esse acesso.</p>' from dual where @mbs_html;
select '<h3>O que a ferramenta faz</h3>' from dual where @mbs_html;
select concat('<p class="leg">O MyBraboSat executa ',@n_tot,' verificacoes somente de leitura contra <code>mysql</code>, <code>information_schema</code> e <code>performance_schema</code>. Nenhuma alteracao e feita no servidor: o script cria apenas uma tabela temporaria de sessao, que desaparece ao desconectar. A coleta dura segundos e pode ser repetida a qualquer momento para acompanhar a evolucao.</p>') from dual where @mbs_html;
select '<h3>Metodo</h3>' from dual where @mbs_html;
select '<p class="leg">Cada verificacao recebe uma severidade e um estado. A severidade reflete o impacto caso o item seja explorado; o estado reflete o que foi encontrado. Itens que dependem do contexto da aplicacao nao sao tratados como falha: vao para uma secao propria, de avaliacao. A nota de postura pondera as falhas pela severidade, de modo que uma unica falha critica pesa mais do que varias de baixa.</p>' from dual where @mbs_html;
select '<h3>Escopo</h3>' from dual where @mbs_html;
select concat('<p class="leg">Servidor <b>',@mbs_servidor,'</b>, MySQL ',@mbs_versao_sql,', coletado em ',
       date_format(@mbs_gerado_em,'%d/%m/%Y as %H:%i'),' pela conta <code>',@mbs_usuario,
       '</code>. Estao fora do escopo: seguranca do sistema operacional, regras de firewall, backup e sua testagem de restauracao, seguranca da aplicacao que consome o banco, e replicas ou nos de cluster nao incluidos nesta coleta.</p>') from dual where @mbs_html;

-- ============================================================== legenda
select '<h2 class="secao" id="legenda">2. Como ler o relatorio<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">As tabelas deste documento usam duas classificacoes. Conhece-las evita a leitura errada mais comum, que e tratar todo apontamento como defeito.</p>' from dual where @mbs_html;
select '<h3>Severidade &mdash; qual o impacto se o item for explorado</h3>' from dual where @mbs_html;
select '<table><tr><th>Severidade</th><th>Peso</th><th>Significado</th></tr>' from dual where @mbs_html;
select '<tr><td><span class="sev s-critica">critica</span></td><td>10</td><td>Permite acesso nao autorizado ao dado ou ao servidor, de forma direta e sem obstaculo. Corrigir antes de qualquer outra coisa.</td></tr>' from dual where @mbs_html;
select '<tr><td><span class="sev s-alta">alta</span></td><td>6</td><td>Amplia bastante a superficie de ataque ou elimina uma barreira importante. Entra no proximo ciclo de mudanca.</td></tr>' from dual where @mbs_html;
select '<tr><td><span class="sev s-media">media</span></td><td>3</td><td>Boa pratica consolidada que nao esta aplicada. Enfraquece defesa em profundidade ou rastreabilidade.</td></tr>' from dual where @mbs_html;
select '<tr><td><span class="sev s-baixa">baixa</span></td><td>1</td><td>Endurecimento incremental. Vale aplicar quando houver janela.</td></tr>' from dual where @mbs_html;
select '<tr><td><span class="sev s-info">info</span></td><td>0</td><td>Inventario e contexto. Nao entra na nota.</td></tr>' from dual where @mbs_html;
select '</table>' from dual where @mbs_html;
select '<h3>Estado &mdash; o que foi encontrado</h3>' from dual where @mbs_html;
select '<table><tr><th>Estado</th><th>Significado</th></tr>' from dual where @mbs_html;
select '<tr><td class="e-PASS">PASS</td><td>A configuracao esta de acordo com a recomendacao.</td></tr>' from dual where @mbs_html;
select '<tr><td class="e-FAIL">FAIL</td><td>A recomendacao nao esta aplicada. Perde o peso inteiro na nota.</td></tr>' from dual where @mbs_html;
select '<tr><td class="e-AVALIAR">AVALIAR</td><td>Depende do contexto: pode ser aceitavel, pode ser risco. Perde metade do peso. Exige decisao humana, nao correcao automatica.</td></tr>' from dual where @mbs_html;
select '<tr><td class="e-NA">NA</td><td>Nao aplicavel a esta versao ou edicao do MySQL.</td></tr>' from dual where @mbs_html;
select '</table>' from dual where @mbs_html;
select concat('<p class="nota-rodape">Nota de postura = 100 x (1 &minus; peso perdido / peso total). Nesta coleta: ',
       @nota,'/100.</p>') from dual where @mbs_html;

-- ============================================================== contexto
select '<h2 class="secao" id="contexto">3. Seguranca em MySQL: por que isto importa<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">O banco de dados e o ultimo lugar onde o dado existe em forma utilizavel. Firewall, WAF e autenticacao da aplicacao sao camadas que protegem o caminho ate ele; quando qualquer uma falha, o que resta e a configuracao do proprio servidor. E ela que decide se o invasor encontra uma copia legivel de tudo ou uma barreira a mais.</p>' from dual where @mbs_html;
select '<p class="leg">Na pratica, os incidentes com MySQL raramente comecam com uma falha exotica do produto. Comecam com o feijao com arroz: conta sem senha que sobrou de uma migracao, conta de aplicacao com privilegio global porque era mais rapido do que calcular o minimo necessario, trafego de replicacao em texto claro entre dois datacenters, binlog sem criptografia num volume que foi descartado sem apagar, ausencia de auditoria que impede saber o que foi acessado depois que o incidente ja aconteceu.</p>' from dual where @mbs_html;
select '<h3>Os quatro eixos avaliados</h3>' from dual where @mbs_html;
select '<p class="leg"><b>Identidade e privilegio.</b> Quem entra e o que pode fazer. O principio e o do menor privilegio: cada conta recebe exatamente o que precisa, nem mais. Privilegios amplos como <code>FILE</code> e <code>SUPER</code> transformam qualquer comprometimento de aplicacao em comprometimento do servidor.</p>' from dual where @mbs_html;
select '<p class="leg"><b>Criptografia.</b> Em transito e em repouso. TLS protege o dado entre aplicacao e banco, e entre no primario e replicas. A criptografia de tablespace, redo, undo e binlog protege o dado quando o meio fisico sai do seu controle, por descarte, roubo ou snapshot de nuvem.</p>' from dual where @mbs_html;
select '<p class="leg"><b>Superficie de ataque.</b> Todo recurso ligado e um recurso que pode ser abusado. <code>local_infile</code>, <code>secure_file_priv</code> vazio, protocolo X ativo sem uso e schemas de teste esquecidos sao portas que ninguem precisa manter abertas.</p>' from dual where @mbs_html;
select '<p class="leg"><b>Rastreabilidade.</b> Auditoria nao impede o incidente; ela responde o que aconteceu. Sem trilha de acesso, a pergunta que a diretoria e o regulador fazem depois do vazamento &mdash; quais dados foram acessados, por quem e quando &mdash; nao tem resposta.</p>' from dual where @mbs_html;
select '<h3>O recorte regulatorio</h3>' from dual where @mbs_html;
select '<p class="leg">A LGPD nao prescreve tecnologia, mas o artigo 46 exige medidas tecnicas aptas a proteger o dado pessoal. Criptografia, controle de acesso e trilha de auditoria sao justamente as evidencias que se apresenta para demonstrar essa aptidao. O CIS Benchmark para MySQL cumpre o papel de baseline reconhecida: e por isso que as verificacoes deste relatorio trazem a referencia CIS correspondente, quando existe.</p>' from dual where @mbs_html;

-- ---------------------------------------------------------------- sumario
select '<h2 class="secao" id="sumario">4. Sumario executivo<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">Retrato da postura em uma tela. A nota pondera as falhas pela severidade; os cartoes mostram a distribuicao. Use esta secao para decidir prioridade, e as duas seguintes para executar.</p>' from dual where @mbs_html;
select concat('<div class="nota ',@classe,'"><div class="v">',@nota,'</div><div><div style="font-size:12px;',
              'letter-spacing:.12em;text-transform:uppercase;color:var(--fg2)">Nota de postura (0&ndash;100)</div>',
              '<div style="margin-top:6px;color:var(--fg)">',@veredito,'</div></div></div>') from dual where @mbs_html;
select concat('<div class="grid">',
   '<div class="card"><div class="n" style="color:#FF8597">',@n_crit,'</div><div class="l">Criticas</div></div>',
   '<div class="card"><div class="n" style="color:var(--err)">',@n_alta,'</div><div class="l">Altas</div></div>',
   '<div class="card"><div class="n" style="color:var(--warn)">',@n_media,'</div><div class="l">Medias</div></div>',
   '<div class="card"><div class="n" style="color:#8FBCFF">',@n_baixa,'</div><div class="l">Baixas</div></div>',
   '<div class="card"><div class="n" style="color:var(--warn)">',@n_aval,'</div><div class="l">A avaliar</div></div>',
   '<div class="card"><div class="n" style="color:var(--ok)">',@n_pass,'</div><div class="l">Conformes</div></div>',
   '<div class="card"><div class="n">',@n_tot,'</div><div class="l">Verificacoes</div></div>',
   '</div>') from dual where @mbs_html;

-- ------------------------------------------------- falhas com remediacao
select '<h2 class="secao" id="falhas">5. Falhas e remediacao<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">Itens em que a recomendacao nao esta aplicada, ordenados por severidade. Cada linha traz o que foi encontrado no servidor, o comando de correcao e o link para a documentacao oficial. Os comandos usam <code>SET PERSIST</code> onde o parametro aceita, o que sobrevive a reinicializacao sem editar arquivo; onde exige <code>my.cnf</code>, isso esta dito na propria linha.</p>' from dual where @mbs_html;
select '<p class="nota-rodape">Antes de aplicar: valide em ambiente de homologacao. Parametros como <code>require_secure_transport</code> e <code>local_infile</code> derrubam conexao de aplicacao que dependa do comportamento antigo.</p>' from dual where @mbs_html;
select if(@n_crit+@n_alta+@n_media+@n_baixa = 0,
   '<div class="vazio">Nenhuma falha. Os itens marcados para avaliacao estao na secao seguinte.</div>','') from dual where @mbs_html;
select if(@n_crit+@n_alta+@n_media+@n_baixa = 0,'',
   '<table><tr><th>Sev</th><th>Verificacao</th><th>O que foi encontrado</th><th>Como corrigir</th><th>Doc</th></tr>') from dual where @mbs_html;
select concat('<tr><td><span class="sev s-',sev,'">',sev,'</span></td>',
              '<td><b>',replace(replace(item,'<','&lt;'),'>','&gt;'),'</b><div class="sub">',dominio,'</div></td>',
              '<td>',replace(replace(ifnull(achado,''),'<','&lt;'),'>','&gt;'),'</td>',
              '<td><code>',replace(replace(ifnull(correcao,'&mdash;'),'<','&lt;'),'>','&gt;'),'</code></td>',
              '<td>',if(doc is null,'&mdash;',concat('<a href="',doc,'" target="_blank">',ifnull(ref,'doc'),'</a>')),'</td></tr>')
  from mbs_achados where estado='FAIL' and @mbs_html
 order by field(sev,'critica','alta','media','baixa','info'), ord;
select if(@n_crit+@n_alta+@n_media+@n_baixa = 0,'','</table>') from dual where @mbs_html;

-- ------------------------------------------------------------ a avaliar
select '<h2 class="secao" id="avaliar">6. Itens para avaliar<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">Nao sao defeitos. Sao decisoes que dependem do desenho da aplicacao e do apetite a risco da empresa &mdash; por exemplo, exigir certificado de cliente em toda conta, ou cifrar o binlog num ambiente onde o volume ja e cifrado pelo storage. Cada item traz a sugestao tecnica; a escolha e de quem conhece o contexto.</p>' from dual where @mbs_html;
select if(@n_aval=0,'<div class="vazio">Nada pendente de avaliacao.</div>',
   '<p>Nao sao falhas: dependem do contexto da sua aplicacao e do apetite a risco da empresa.</p>') from dual where @mbs_html;
select if(@n_aval=0,'','<table><tr><th>Sev</th><th>Verificacao</th><th>Situacao</th><th>Sugestao</th><th>Doc</th></tr>') from dual where @mbs_html;
select concat('<tr><td><span class="sev s-',sev,'">',sev,'</span></td>',
              '<td><b>',replace(replace(item,'<','&lt;'),'>','&gt;'),'</b><div class="sub">',dominio,'</div></td>',
              '<td>',replace(replace(ifnull(achado,''),'<','&lt;'),'>','&gt;'),'</td>',
              '<td><code>',replace(replace(ifnull(correcao,'&mdash;'),'<','&lt;'),'>','&gt;'),'</code></td>',
              '<td>',if(doc is null,'&mdash;',concat('<a href="',doc,'" target="_blank">',ifnull(ref,'doc'),'</a>')),'</td></tr>')
  from mbs_achados where estado='AVALIAR' and @mbs_html
 order by field(sev,'critica','alta','media','baixa','info'), ord;
select if(@n_aval=0,'','</table>') from dual where @mbs_html;

-- -------------------------------------------------------- todos os checks
select '<h2 class="secao" id="todas">7. Todas as verificacoes<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">A lista completa, inclusive o que passou. Serve como evidencia de cobertura em auditoria: mostra nao apenas o que falhou, mas tudo o que foi examinado.</p>' from dual where @mbs_html;
select '<table><tr><th>Dominio</th><th>Verificacao</th><th>Sev</th><th>Estado</th><th>Detalhe</th></tr>' from dual where @mbs_html;
select concat('<tr><td>',dominio,'</td><td>',replace(replace(item,'<','&lt;'),'>','&gt;'),'</td>',
              '<td><span class="sev s-',sev,'">',sev,'</span></td>',
              '<td class="e-',estado,'">',estado,'</td>',
              '<td>',replace(replace(ifnull(achado,''),'<','&lt;'),'>','&gt;'),'</td></tr>')
  from mbs_achados where @mbs_html order by ord;
select '</table>' from dual where @mbs_html;

-- ============================================================================
--  INVENTARIO — contexto para quem le o relatorio
-- ============================================================================

select '<h2 class="secao" id="inventario">8. Inventario do servidor<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">Contexto tecnico para quem le o relatorio sem ter acesso ao servidor. Util tambem como anexo de auditoria: registra a versao exata, as contas existentes e o volume de dado no momento da coleta.</p>' from dual where @mbs_html;

select '<h3>Identificacao</h3><table><tr><th>Item</th><th>Valor</th></tr>' from dual where @mbs_html;
select concat('<tr><td>',n,'</td><td><code>',v,'</code></td></tr>') from (
  select 'Versao' n, convert(version() using utf8mb4) v union all
  select 'Distribuicao', convert(@@version_comment using utf8mb4) union all
  select 'Hostname', convert(@@hostname using utf8mb4) union all
  select 'Porta', convert(cast(@@port as char) using utf8mb4) union all
  select 'Datadir', convert(@@datadir using utf8mb4) union all
  select 'Diretorio base', convert(@@basedir using utf8mb4) union all
  select 'Charset do servidor', convert(@@character_set_server using utf8mb4) union all
  select 'Collation', convert(@@collation_server using utf8mb4) union all
  select 'Fuso horario', convert(@@system_time_zone using utf8mb4) union all
  select 'Uptime', convert(concat(round(v2.VARIABLE_VALUE/86400,1),' dia(s)') using utf8mb4)
    from performance_schema.global_status v2 where v2.VARIABLE_NAME='Uptime'
) t where @mbs_html;
select '</table>' from dual where @mbs_html;

select '<p class="leg" style="margin-top:18px"><b>Contas.</b> A coluna SSL mostra se a conta exige conexao cifrada por si so; quando esta vazia, a protecao depende apenas do parametro global. A coluna de plugin identifica o metodo de autenticacao.</p>' from dual where @mbs_html;
select '<h3>Contas</h3><table><tr><th>Conta</th><th>Plugin</th><th>Travada</th><th>SSL</th><th>Expira</th><th>Senha alterada em</th></tr>' from dual where @mbs_html;
select concat('<tr><td><code>',user,'@',host,'</code></td><td>',plugin,'</td>',
              '<td>',if(account_locked='Y','sim','<span class="e-FAIL">nao</span>'),'</td>',
              '<td>',if(ssl_type='','<span class="e-AVALIAR">nenhum</span>',ssl_type),'</td>',
              '<td>',ifnull(cast(password_lifetime as char),'padrao'),'</td>',
              '<td>',ifnull(cast(password_last_changed as char),'&mdash;'),'</td></tr>')
  from mysql.user where @mbs_html order by user, host;
select '</table>' from dual where @mbs_html;

select '<h3>Schemas e tamanho</h3><table><tr><th>Schema</th><th>Tabelas</th><th>Dados (MB)</th><th>Indice (MB)</th><th>Engines</th></tr>' from dual where @mbs_html;
select concat('<tr><td><b>',table_schema,'</b></td><td>',count(*),'</td>',
              '<td>',round(sum(data_length)/1024/1024,1),'</td>',
              '<td>',round(sum(index_length)/1024/1024,1),'</td>',
              '<td>',group_concat(distinct engine separator ', '),'</td></tr>')
  from information_schema.tables
 where table_schema not in ('information_schema','performance_schema') and @mbs_html
 group by table_schema order by sum(data_length) desc;
select '</table>' from dual where @mbs_html;

select '<h3>Maiores tabelas</h3><table><tr><th>Tabela</th><th>Engine</th><th>Linhas (aprox.)</th><th>Total (MB)</th><th>Cifrada</th></tr>' from dual where @mbs_html;
select concat('<tr><td><code>',table_schema,'.',table_name,'</code></td><td>',ifnull(engine,'&mdash;'),'</td>',
              '<td>',format(ifnull(table_rows,0),0),'</td>',
              '<td>',round((ifnull(data_length,0)+ifnull(index_length,0))/1024/1024,1),'</td>',
              '<td>',if(create_options like '%ENCRYPTION="Y"%','<span class="e-PASS">sim</span>','<span class="e-AVALIAR">nao</span>'),'</td></tr>')
  from information_schema.tables
 where table_schema not in ('information_schema','performance_schema','mysql','sys')
   and table_type='BASE TABLE' and @mbs_html
 order by (ifnull(data_length,0)+ifnull(index_length,0)) desc limit 20;
select '</table>' from dual where @mbs_html;

select '<p class="leg" style="margin-top:18px"><b>Parametros.</b> Os valores abaixo sao os que estavam em vigor na coleta. Compare com o <code>my.cnf</code>: divergencia entre os dois indica parametro alterado em tempo de execucao que voltara ao antigo no proximo restart.</p>' from dual where @mbs_html;
select '<h3>Parametros de seguranca</h3><table><tr><th>Parametro</th><th>Valor</th></tr>' from dual where @mbs_html;
select concat('<tr><td><code>',variable_name,'</code></td><td><code>',
              if(variable_value='','(vazio)',replace(replace(variable_value,'<','&lt;'),'>','&gt;')),'</code></td></tr>')
  from performance_schema.global_variables
 where variable_name in ('require_secure_transport','tls_version','ssl_cert','ssl_ca','local_infile',
                         'secure_file_priv','skip_name_resolve','sql_mode','general_log','log_bin',
                         'binlog_encryption','innodb_redo_log_encrypt','innodb_undo_log_encrypt',
                         'default_password_lifetime','password_history','password_reuse_interval',
                         'validate_password.policy','validate_password.length','authentication_policy',
                         'partial_revokes','activate_all_roles_on_login','automatic_sp_privileges',
                         'max_connections','max_user_connections','connect_timeout','wait_timeout')
   and @mbs_html
 order by variable_name;
select '</table>' from dual where @mbs_html;

select '<h2 class="secao" id="limites">9. Limitacoes e proximos passos<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">Esta avaliacao le configuracao. Ela nao tenta explorar nada, nao mede a forca das senhas realmente em uso (apenas se ha politica que as exija), nao verifica se o backup restaura, e nao enxerga o que acontece fora do servidor: regra de firewall, permissao de arquivo no sistema operacional, segredo em codigo da aplicacao.</p>' from dual where @mbs_html;
select '<p class="leg">O encaminhamento natural, em ordem: (1) tratar as falhas criticas e altas em janela de mudanca, comecando pelas de identidade e privilegio; (2) decidir os itens em avaliacao com quem conhece a aplicacao, registrando a decisao &mdash; aceitar risco de forma consciente e documentada e uma resposta valida; (3) repetir esta coleta apos as mudancas e comparar a nota; (4) complementar com teste de restauracao de backup e revisao das regras de rede, que estao fora do alcance desta ferramenta.</p>' from dual where @mbs_html;

select '<h2 class="secao" id="referencias">10. Referencias<a class="topo-link" href="#indice">voltar ao indice</a></h2>' from dual where @mbs_html;
select '<p class="leg">Fontes usadas nas recomendacoes deste documento. Os links da coluna Doc em cada tabela apontam para a pagina especifica do parametro ou recurso tratado.</p>' from dual where @mbs_html;
select '<table><tr><th>Fonte</th><th>Para que serve</th></tr>' from dual where @mbs_html;
select '<tr><td><a href="https://dev.mysql.com/doc/refman/8.4/en/security.html" target="_blank">MySQL Reference Manual &mdash; Security</a></td><td>Capitulo de seguranca da documentacao oficial.</td></tr>' from dual where @mbs_html;
select '<tr><td><a href="https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html" target="_blank">Security Guidelines</a></td><td>Recomendacoes gerais da Oracle para endurecer a instalacao.</td></tr>' from dual where @mbs_html;
select '<tr><td><a href="https://dev.mysql.com/doc/refman/8.4/en/mysql-nutshell.html" target="_blank">What Is New in MySQL 8.4</a></td><td>Removidos e depreciados que afetam seguranca (ssl, have_ssl, default_authentication_plugin).</td></tr>' from dual where @mbs_html;
select '<tr><td><a href="https://www.cisecurity.org/benchmark/oracle_mysql" target="_blank">CIS Oracle MySQL Benchmark</a></td><td>Baseline de configuracao usado nas colunas de referencia.</td></tr>' from dual where @mbs_html;
select '<tr><td><a href="https://www.cvedetails.com/vendor/185/Mysql.html" target="_blank">CVE Details &mdash; MySQL</a></td><td>Confira CVEs da sua versao exata e planeje o patch.</td></tr>' from dual where @mbs_html;
select '<tr><td><a href="https://www.gov.br/anpd/pt-br" target="_blank">ANPD &mdash; LGPD</a></td><td>Art. 46: medidas tecnicas de protecao do dado pessoal.</td></tr>' from dual where @mbs_html;
select '</table>' from dual where @mbs_html;

select concat('<footer>MyBraboSat ',@mbs_versao,' &middot; by &bull; DBA BRABO &middot; ',
              'relatorio gerado em ',date_format(@mbs_gerado_em,'%d/%m/%Y %H:%i:%s'),'<br>',
              'Inspirado no <a href="https://github.com/meob/MySAT" target="_blank">MySAT</a> ',
              '(XeniaLAB srl, licenca MIT). Este derivado tambem e MIT.<br>',
              'Documento confidencial: contem o retrato da postura de seguranca do banco.</footer>') from dual where @mbs_html;
select '</div></body></html>' from dual where @mbs_html;

-- ============================================================================
--  RELATORIO EM TEXTO — para ler no terminal (@mbs_formato = 'txt')
--
--  Mesmos achados, mesma nota e mesma ordem do HTML, em texto puro de ate
--  100 colunas: sem cor, sem tabulacao e sem quebra de linha dentro de um
--  valor. Em modo batch o cliente mysql escreve TAB e quebra de linha de um
--  valor como "\t" e "\n" literais; por isso cada linha do relatorio e uma
--  linha do resultado, e os blocos de varias linhas sao montados por JOIN
--  com uma lista de numeros (uma linha do bloco por numero).
-- ============================================================================

set @t_linha = repeat('=',100);
set @t_fina  = repeat('-',100);

select @t_linha from dual where @mbs_txt;
select concat(' MyBraboSat ',@mbs_versao,' - MySQL Security Assessment',
              lpad('by * DBA BRABO  ',100-length(concat(' MyBraboSat ',@mbs_versao,' - MySQL Security Assessment')),' '))
  from dual where @mbs_txt;
select @t_linha from dual where @mbs_txt;
select concat(' Servidor .......: ',@mbs_servidor) from dual where @mbs_txt;
select concat(' Versao do MySQL : ',@mbs_versao_sql,' (',convert(@@version_comment using utf8mb4),')') from dual where @mbs_txt;
select concat(' Data da coleta .: ',date_format(@mbs_gerado_em,'%d/%m/%Y %H:%i'),'   por ',@mbs_usuario) from dual where @mbs_txt;
select ' Classificacao ..: ALTAMENTE CONFIDENCIAL - mapa das fraquezas deste servidor' from dual where @mbs_txt;
select @t_fina from dual where @mbs_txt;
select concat(' NOTA DE POSTURA : ',@nota,'/100  (',upper(@classe),')') from dual where @mbs_txt;
select concat(' ',@veredito) from dual where @mbs_txt;
select '' from dual where @mbs_txt;
select concat(' Falhas: critica ',@n_crit,' | alta ',@n_alta,' | media ',@n_media,' | baixa ',@n_baixa,
              '     Avaliar: ',@n_aval,'     OK: ',@n_pass,'     Verificacoes: ',@n_tot)
  from dual where @mbs_txt;
select ' Peso por severidade: critica 10, alta 6, media 3, baixa 1. FAIL perde o peso, AVALIAR perde metade.'
  from dual where @mbs_txt;
select @t_linha from dual where @mbs_txt;

-- ------------------------------------------------------------- falhas
select '' from dual where @mbs_txt;
select ' 1. FALHAS E REMEDIACAO  (da mais grave para a menos grave)' from dual where @mbs_txt;
select @t_fina from dual where @mbs_txt;
select if(@n_crit+@n_alta+@n_media+@n_baixa = 0,' Nenhuma falha encontrada.','') from dual where @mbs_txt;
-- Uma linha do resultado por linha do texto (ver o cabecalho deste bloco).
-- JOIN com 1..5 em vez de UNION: tabela TEMPORARY nao pode aparecer duas
-- vezes na mesma consulta (ERROR 1137 Can't reopen table: 'mbs_achados').
select case n.p
         when 1 then concat(' [',rpad(upper(a.sev),7,' '),'] ',a.item,'  (',a.dominio,')')
         when 2 then concat('     Achado ...: ',ifnull(a.achado,'-'))
         when 3 then concat('     Correcao .: ',ifnull(a.correcao,'-'))
         when 4 then concat('     Referencia: ',ifnull(a.doc,'-'),if(a.ref is null,'',concat('  (',a.ref,')')))
         else '' end
  from mbs_achados a
  join (select 1 p union all select 2 union all select 3 union all select 4 union all select 5) n
 where a.estado='FAIL' and @mbs_txt
 order by field(a.sev,'critica','alta','media','baixa','info'), a.ord, n.p;

-- ------------------------------------------------------------ a avaliar
select ' 2. ITENS PARA AVALIAR  (dependem do contexto da aplicacao; nao sao defeitos)' from dual where @mbs_txt;
select @t_fina from dual where @mbs_txt;
select if(@n_aval=0,' Nada pendente de avaliacao.','') from dual where @mbs_txt;
select case n.p
         when 1 then concat(' [',rpad(upper(a.sev),7,' '),'] ',a.item,'  (',a.dominio,')')
         when 2 then concat('     Situacao .: ',ifnull(a.achado,'-'))
         when 3 then concat('     Sugestao .: ',ifnull(a.correcao,'-'))
         else '' end
  from mbs_achados a
  join (select 1 p union all select 2 union all select 3 union all select 4) n
 where a.estado='AVALIAR' and @mbs_txt
 order by field(a.sev,'critica','alta','media','baixa','info'), a.ord, n.p;

-- -------------------------------------------------------- todos os checks
select ' 3. TODAS AS VERIFICACOES  (evidencia de cobertura, inclusive o que passou)' from dual where @mbs_txt;
select @t_fina from dual where @mbs_txt;
select concat(' ',rpad('ESTADO',8,' '),rpad('SEV',9,' '),rpad('DOMINIO',24,' '),'VERIFICACAO') from dual where @mbs_txt;
select concat(' ',rpad(estado,8,' '),rpad(sev,9,' '),rpad(left(dominio,23),24,' '),item)
  from mbs_achados where @mbs_txt order by ord;

-- ------------------------------------------------------------ inventario
select '' from dual where @mbs_txt;
select ' 4. INVENTARIO DO SERVIDOR' from dual where @mbs_txt;
select @t_fina from dual where @mbs_txt;
select concat(' ',rpad(n,22,'.'),' ',v) from (
  select 'Versao' n, convert(version() using utf8mb4) v union all
  select 'Distribuicao', convert(@@version_comment using utf8mb4) union all
  select 'Hostname', convert(@@hostname using utf8mb4) union all
  select 'Porta', convert(cast(@@port as char) using utf8mb4) union all
  select 'Datadir', convert(@@datadir using utf8mb4) union all
  select 'Charset do servidor', convert(@@character_set_server using utf8mb4) union all
  select 'Uptime', convert(concat(round(v2.VARIABLE_VALUE/86400,1),' dia(s)') using utf8mb4)
    from performance_schema.global_status v2 where v2.VARIABLE_NAME='Uptime'
) t where @mbs_txt;
select '' from dual where @mbs_txt;
select concat(' ',rpad('CONTA',40,' '),rpad('PLUGIN',26,' '),rpad('TRAVADA',9,' '),'SSL') from dual where @mbs_txt;
select concat(' ',rpad(left(concat(user,'@',host),39),40,' '),rpad(left(plugin,25),26,' '),
              rpad(if(account_locked='Y','sim','nao'),9,' '),if(ssl_type='','nenhum',ssl_type))
  from mysql.user where @mbs_txt order by user, host;
select '' from dual where @mbs_txt;
select concat(' ',rpad('PARAMETRO',36,' '),'VALOR') from dual where @mbs_txt;
select concat(' ',rpad(variable_name,36,' '),if(variable_value='','(vazio)',variable_value))
  from performance_schema.global_variables
 where variable_name in ('require_secure_transport','tls_version','local_infile','secure_file_priv',
                         'skip_name_resolve','general_log','log_bin','binlog_encryption',
                         'innodb_redo_log_encrypt','innodb_undo_log_encrypt','default_password_lifetime',
                         'password_history','password_reuse_interval','validate_password.policy',
                         'validate_password.length','authentication_policy','partial_revokes')
   and @mbs_txt
 order by variable_name;

select '' from dual where @mbs_txt;
select @t_linha from dual where @mbs_txt;
select ' Esta avaliacao le configuracao: nao explora nada, nao testa a forca das senhas em uso, nao' from dual where @mbs_txt;
select ' verifica restauracao de backup nem enxerga firewall, permissao de arquivo ou segredo na aplicacao.' from dual where @mbs_txt;
select ' Relatorio completo (capa, indice, legendas, links, PDF): gere em HTML (@mbs_formato = html).' from dual where @mbs_txt;
select concat(' MyBraboSat ',@mbs_versao,' * by DBA BRABO * gerado em ',
              date_format(@mbs_gerado_em,'%d/%m/%Y %H:%i:%s'),' * inspirado no MySAT (MIT)')
  from dual where @mbs_txt;
select @t_linha from dual where @mbs_txt;

drop temporary table if exists mbs_achados;

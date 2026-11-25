# dcinfo

Модуль NetExec (nxc) для поиска контроллера домена через обычную доменную учётку на произвольной машине домена. RPC-вызовы к штатным интерфейсам Windows.

# Модуль `dcinfo` — где контроллер домена

```
nxc smb 10.0.0.50 -u user -p 'Passw0rd' -M dcinfo
```

```
[*] DC discovery for CORP.LOCAL  (SMB/RPC, no admin rights, nothing executed on target)
      domain DN          : DC=corp,DC=local
      functional level   : Windows Server 2016 / 2019 / 2022 / 2025
      target             : 10.0.0.50 -> ws01.corp.local [10.0.0.50]
      DNS servers used   : 10.0.0.5
      discovery channel  : SMB/RPC via dssetup + netlogon DsrGetDcNameEx2 + netlogon DsrGetSiteName
      target role        : MemberWorkstation  site=Branch
[+] DC from target locator: dc01.corp.local [10.0.0.5] site=Default-First-Site-Name flags=LDAP, DS, KDC, TIMESERV, WRITABLE
[+] Domain controllers found: 2
[+]   DC dc01.corp.local [10.0.0.5] site=Default-First-Site-Name roles=ldap,kerberos,gc,pdc
[+]   DC dc02.corp.local [10.0.0.6] site=Branch roles=ldap,kerberos,gc
```

## Почему это тихо и почему не `-x nslookup`

`nxc smb ... -x nslookup` — это удалённое исполнение: нужен администратор на цели, создаётся процесс `nslookup.exe` (CmdLine, ParentProcess, дерево процессов). Это ровно тот шаблон, который ловят EDR/AV, и ровно то, чего не бывает без админских прав.

| | `-x nslookup` | `dcinfo` |
|---|---|---|
| Права на цели | администратор | обычная доменная учётка |
| Что появляется на цели | процесс `nslookup.exe` | ничего |
| Что видит EDR | LOLBin + командная строка | штатный RPC-вызов DC-локатора |
| Что вернёт | DNS-серверы из конфигурации цели | FQDN/IP/сайт/роли именно контроллеров |

## Как работает SMB-путь

1. **`\pipe\dssetup` → `DsRolerGetPrimaryDomainInformation`** (MS-DSSP, opnum 0): роль машины, DNS-имя домена, лес, GUID домена — тот же вызов, что за `NetGetJoinInformation`.
2. **`\pipe\netlogon` → `DsrGetDcNameEx2`** (MS-NRPC, opnum 34). По спецификации MS-NRPC сервер, принявший вызов, «не обязан быть контроллером домена»: цель сама делает DNS SRV `_ldap._tcp.dc._msdcs` и LDAP-ping до DC и возвращает `DOMAIN_CONTROLLER_INFOW` — FQDN контроллера, его IP, сайт DC и сайт клиента, флаги PDC/GC/KDC/WRITABLE.
3. **`DsrGetSiteName`** (opnum 28) — сайт самой цели.
4. Обогащение: IP контроллера используется как DNS-сервер (UDP/53) для SRV-запросов, поэтому в отчёт попадают **все** DC домена и их сайты. С `LDAP=True` дополнительно читаются RootDSE, `CN=Sites` и (по `ZONES=True`) AD-интегрированные DNS-зоны.

Права: на рабочей станции `NETLOGON_WKSTA_RPC_ACCESS`, на DC `NETLOGON_DCLOC_RPC_ACCESS` — те же маски, под которыми выполняется обычный доменный вход. Транспорт сначала садится на уже аутентифицированную SMB-сессию nxc, при отказе поднимает второе соединение с теми же кредами (пароль, `-H`, Kerberos).

## Опции

| Опция | По умолчанию | Описание |
|---|---|---|
| `DOMAIN` | из RPC/LDAP | DNS-имя домена, если автоопределение не сработало |
| `DNS` | IP найденного DC + системные | список DNS-серверов через запятую |
| `LDAP` | `True` | SMB-путь: дочитывать RootDSE/сайты/зоны по LDAP |
| `SITES` | `True` | перечислять подсети/сайты из `CN=Sites` |
| `ZONES` | `False` | читать A/AAAA из AD-интегрированных DNS-зон |
| `ZONE_LIMIT` | `400` | максимум записей при `ZONES=True` |
| `TIMEOUT` / `RETRIES` | `2` / `2` | таймаут и повторы DNS |
| `DEBUG` | `False` | печатать каждый шаг: какие резолверы, что вернул SRV, сработал ли LDAP-фолбэк |

Если DNS-сервер не отдаёт SRV (UDP/53 режется, DC не держит DNS, зона не та), список DC строится из самого каталога: `CN=Sites,CN=Configuration` → `CN=Servers` → `dNSHostName`. Предупреждение в отчёте теперь показывает, какие резолверы пробовали, и что в этом случае делать.

В отчёте есть строка `DC reachability` — быстрый TCP-пробник портов 53/389/445 до найденного DC. Если 53 и 389 закрыты (типичная сегментация: цель в 172.23.94.0/24, DC в 172.22.1.0/24), модуль прямо пишет, что доступен только ответ локатора — и это нормально, IP и DNS-имя DC уже получены.

## Резервные пути

| Шаг | Если недоступен |
|---|---|
| `dssetup` | домен берётся из `connection.domain` (nxc) |
| `DsrGetDcNameEx2` | `NetrGetAnyDCName` → имя DC (NetBIOS), IP добирается DNS/NBT |
| `DsrGetSiteName` | сайт берётся из `ClientSiteName` ответа локатора |
| UDP/53 | повтор по TCP/53 |
| DNS SRV | список DC из `CN=Sites`/`CN=Servers` по LDAP |
| LDAP-обогащение | остаётся SMB-результат + DNS SRV через IP DC |

---

# Установка

```bash
# Linux / macOS
cp dcinfo.py ~/.nxc/modules/

# Windows
copy dcinfo.py %USERPROFILE%\.nxc\modules\
```

Проверка:

```bash
nxc smb --list-modules | grep -E 'dcinfo'
```


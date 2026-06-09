# Windows Security Log Triage Script

## Features

- Parses Windows Security Event ID 4688.
- Extracts key fields:
  - Time
  - User
  - Parent Process
  - Process
  - CommandLine
- Detects suspicious PowerShell usage.
- Detects high-risk PowerShell patterns:
  - EncodedCommand
  - WindowStyle Hidden
  - ExecutionPolicy Bypass
  - NoProfile
- Detects discovery commands:
  - whoami
  - hostname
  - ipconfig
  - systeminfo
  - nltest
  - net
- Detects cmd discovery chains.
- Detects child discovery processes spawned by `cmd.exe`.
- Supports multiple indicators per event.
- Adds Severity, Verdict, Reason, and TriageNote fields.
- Decodes PowerShell EncodedCommand when possible.
- Exports suspicious events to a CSV report.

## Example Indicators

- `HIGH_RISK_POWERSHELL_ENCODED`
- `HIGH_RISK_HIDDEN_POWERSHELL`
- `SUSPICIOUS_POWERSHELL_BYPASS`
- `SUSPICIOUS_POWERSHELL_NOPROFILE`
- `CMD_DISCOVERY_CHAIN`
- `CHILD_DISCOVERY_FROM_CMD`
- `DISCOVERY_COMMAND`
- `POWERSHELL_TO_CMD`

## Цель проекта

Скрипт помогает быстро находить подозрительные события запуска процессов в Windows Security Logs.

Он не заменяет полноценный SIEM или EDR, но показывает базовую логику SOC triage:

- что запустилось;
- кто запустил;
- какой был родительский процесс;
- какая была командная строка;
- какие подозрительные признаки найдены;
- насколько событие важно;
- почему оно отмечено;
- какой контекст стоит проверить аналитику.

## Что делает скрипт

Скрипт:

- читает события **Windows Security Event ID 4688**;
- вытаскивает ключевые поля:
  - Time;
  - User;
  - Parent Process;
  - Process;
  - CommandLine;
- ищет подозрительные PowerShell-паттерны;
- ищет high-risk PowerShell-паттерны;
- ищет discovery-команды;
- анализирует parent-child цепочки процессов;
- поддерживает несколько индикаторов на одно событие;
- добавляет Severity;
- добавляет Verdict;
- добавляет Reason;
- добавляет TriageNote;
- декодирует PowerShell `EncodedCommand`, если это возможно;
- экспортирует suspicious-only события в CSV-отчёт.

## Какие события анализируются

Скрипт работает с Windows Security Log:

```powershell
LogName = Security
Event ID = 4688
```

Event ID 4688 отвечает за создание нового процесса.

Пример события:

```text
Parent:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process:     C:\Windows\System32\cmd.exe
CommandLine: "C:\Windows\System32\cmd.exe" /c whoami
```

Такое событие может означать запуск discovery-команды через цепочку:

```text
PowerShell -> cmd.exe -> whoami.exe
```

## Детектируемые индикаторы

### PowerShell

Скрипт ищет следующие PowerShell-паттерны:

- `SUSPICIOUS_POWERSHELL_BYPASS`
- `SUSPICIOUS_POWERSHELL_NOPROFILE`
- `HIGH_RISK_POWERSHELL_ENCODED`
- `HIGH_RISK_HIDDEN_POWERSHELL`

Примеры команд:

```powershell
powershell.exe -NoProfile
powershell.exe -ExecutionPolicy Bypass
powershell.exe -EncodedCommand <base64>
powershell.exe -WindowStyle Hidden
```

### Discovery-команды

Скрипт ищет базовые команды разведки:

- `whoami`
- `hostname`
- `ipconfig`
- `systeminfo`
- `nltest`
- `net`

Примеры индикаторов:

- `DISCOVERY_COMMAND`
- `CMD_DISCOVERY_CHAIN`
- `CHILD_DISCOVERY_FROM_CMD`
- `POWERSHELL_TO_CMD`

## Примеры логики

### Прямой запуск discovery-команды

```text
Parent:  powershell.exe
Process: whoami.exe
```

Результат:

```text
Indicators: DISCOVERY_COMMAND
Severity:   Low
Verdict:    ПОДОЗРИТЕЛЬНО
Reason:     Common discovery command was executed
```

### Discovery через cmd.exe

```text
Parent:      powershell.exe
Process:     cmd.exe
CommandLine: cmd.exe /c whoami
```

Результат:

```text
Indicators: CMD_DISCOVERY_CHAIN, POWERSHELL_TO_CMD
Severity:   Medium
Verdict:    ПОДОЗРИТЕЛЬНО
Reason:     cmd.exe executed a discovery command through /c; PowerShell spawned cmd.exe
```

### EncodedCommand

```text
CommandLine: powershell.exe -EncodedCommand <base64>
```

Результат:

```text
DecodedCmd:  Write-Host SOC_TEST_ENCODED
Indicators:  HIGH_RISK_POWERSHELL_ENCODED
Severity:    High
Verdict:     СРОЧНО
Reason:      PowerShell used encoded command execution
TriageNote:  EXPECTED_LAB_TEST_ACTIVITY - generated during SOC training
```

## Severity Logic

| Severity | Значение |
|---|---|
| High | High-risk PowerShell поведение |
| Medium | Подозрительный PowerShell или shell/discovery цепочка |
| Low | Базовые discovery-команды |
| Info | Подозрительный паттерн не найден |

## Verdict

Скрипт использует три базовых вердикта:

- `ШУМ`
- `ПОДОЗРИТЕЛЬНО`
- `СРОЧНО`

Важно: Severity и Verdict не являются финальным доказательством инцидента.

Например:

```text
Severity: High
Verdict:  СРОЧНО
```

может означать:

- вредоносную активность;
- легитимный установщик;
- админский скрипт;
- EDR/management tool;
- учебный тест.

Поэтому в скрипте есть поле `TriageNote`.

## TriageNote

`TriageNote` добавляет контекст для аналитика.

### Примеры

```text
EXPECTED_LAB_TEST_ACTIVITY - generated during SOC training
```

Учебная активность, созданная вручную во время SOC-практики.

```text
LIKELY_LEGIT_VSCODE_INSTALLER_OR_UPDATE - verify if VS Code install/update was expected
```

Похоже на легитимный установщик или обновление Visual Studio Code.

```text
TEMP_PARENT_WITH_SUSPICIOUS_POWERSHELL - review parent file, hash, signature and user activity
```

PowerShell был запущен из временной директории с подозрительными параметрами. Нужно проверить родительский файл, хэш, подпись и действия пользователя.

```text
HIGH_RISK_POWERSHELL - investigate immediately
```

High-risk PowerShell без дополнительного понятного контекста. Нужно расследовать сразу.

```text
DISCOVERY_ACTIVITY - correlate with logon events and parent process
```

Обнаружена discovery-активность. Нужно связать событие с логинами и родительским процессом.

## Почему High не всегда инцидент

Скрипт специально не понижает Severity, даже если событие похоже на учебное или легитимное.

Пример:

```text
Indicators: HIGH_RISK_POWERSHELL_ENCODED
Severity:   High
Verdict:    СРОЧНО
TriageNote: EXPECTED_LAB_TEST_ACTIVITY - generated during SOC training
```

Это значит:

- техника опасная;
- контекст учебный;
- финальный вывод делает аналитик.

Это важная часть SOC-мышления: alert severity не равен final incident severity.

## Использование

Запуск скрипта:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows_4688_triage.ps1
```

Запуск с увеличенным количеством событий:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\windows_4688_triage.ps1 -MaxEvents 300
```

Запуск с пользовательским путём отчёта:

```powershell
powershell.exe -ExecutionPolicy Bypass `
    -File .\windows_4688_triage.ps1 `
    -MaxEvents 300 `
    -ReportPath .\reports\soc_4688_triage_report.csv
```

## Параметры

| Параметр | Описание |
|---|---|
| `MaxEvents` | Количество последних событий 4688 для анализа |
| `ReportPath` | Путь для сохранения CSV-отчёта |

## Поля вывода

Скрипт выводит:

- Time
- User
- Parent
- Process
- CommandLine
- DecodedCommand
- Indicators
- Severity
- Verdict
- Reason
- TriageNote

## CSV-отчёт

Скрипт экспортирует найденные подозрительные события в CSV.

Пример пути:

```text
.\reports\soc_4688_triage_report.csv
```

CSV можно открыть в:

- Excel;
- LibreOffice Calc;
- VS Code;
- PowerShell;
- SIEM-like анализе на следующих этапах.

## Пример PowerShell summary

Скрипт показывает сводку по severity:

```text
=== Summary by Severity ===

Name    Count
High    2
Medium  8
Low     2
```

Также можно группировать по индикаторам:

```text
=== Summary by Indicators ===

Count Name
2     DISCOVERY_COMMAND
2     CMD_DISCOVERY_CHAIN, POWERSHELL_TO_CMD
1     HIGH_RISK_POWERSHELL_ENCODED
```

## Ограничения

Скрипт не является полноценным EDR или SIEM.

Он не делает:

- проверку хэшей через VirusTotal;
- проверку цифровых подписей;
- корреляцию с сетевыми событиями;
- корреляцию с 4624/4625/4634;
- анализ Sysmon;
- полноценное MITRE ATT&CK mapping;
- автоматическое подтверждение инцидента.

Это учебный triage-helper для базового анализа Windows Security Logs.

## Что можно добавить дальше

Идеи для развития:

- корреляция 4688 с 4624 по LogonId;
- добавление Sysmon Event ID 1;
- добавление Sysmon Event ID 3 для сетевых соединений;
- проверка цифровой подписи parent/process файлов;
- проверка хэшей;
- MITRE ATT&CK mapping;
- HTML-отчёт;
- JSON-экспорт;
- allowlist для известных легитимных установщиков;
- suspicious-only режим;
- risk score;
- timeline mode.

## Учебный вывод

Проект показывает базовую SOC-логику:

```text
Event
-> Context
-> Indicators
-> Severity
-> Verdict
-> Reason
-> TriageNote
-> Report
```

Главная идея:

> Не каждое подозрительное событие является инцидентом. Но каждое подозрительное событие требует контекста.

## Статус проекта

**Версия:** v0.8

Текущие возможности:

- 4688 parsing;
- suspicious-only filtering;
- PowerShell detection;
- discovery detection;
- parent-child process analysis;
- EncodedCommand decoding;
- severity/verdict/reason;
- contextual triage notes;
- CSV export.

## Cases

- [Windows 4688 Suspicious PowerShell Case](cases/windows-4688-suspicious-powershell/case_report.md)

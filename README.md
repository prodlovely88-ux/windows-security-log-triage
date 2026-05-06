\# Windows Security Log Triage Script



PowerShell-based SOC triage helper for Windows Security Event ID 4688.



\## Purpose



This script parses Windows Security process creation events and highlights suspicious activity based on command line, parent process and process execution patterns.



\## Features



\- Parses Windows Security Event ID 4688

\- Extracts Time, User, Parent Process, Process and CommandLine

\- Detects suspicious PowerShell usage

\- Detects high-risk PowerShell patterns:

&#x20; - EncodedCommand

&#x20; - WindowStyle Hidden

&#x20; - ExecutionPolicy Bypass

&#x20; - NoProfile

\- Detects discovery commands:

&#x20; - whoami

&#x20; - hostname

&#x20; - ipconfig

&#x20; - systeminfo

&#x20; - nltest

&#x20; - net

\- Detects cmd discovery chains

\- Detects child discovery processes spawned by cmd.exe

\- Supports multiple indicators per event

\- Adds Severity, Verdict, Reason and TriageNote

\- Decodes PowerShell EncodedCommand when possible

\- Exports suspicious events to CSV



\## Example Indicators



\- HIGH\_RISK\_POWERSHELL\_ENCODED

\- HIGH\_RISK\_HIDDEN\_POWERSHELL

\- SUSPICIOUS\_POWERSHELL\_BYPASS

\- SUSPICIOUS\_POWERSHELL\_NOPROFILE

\- CMD\_DISCOVERY\_CHAIN

\- CHILD\_DISCOVERY\_FROM\_CMD

\- DISCOVERY\_COMMAND

\- POWERSHELL\_TO\_CMD



\## Severity Logic



\- High: high-risk PowerShell behavior

\- Medium: suspicious PowerShell or shell-based discovery chain

\- Low: basic discovery commands

\- Info: no suspicious pattern matched



\## Important SOC Note



High severity does not always mean confirmed incident.  

The script adds TriageNote to help distinguish suspicious technique from known context such as lab activity or legitimate VS Code installer/update behavior.



\## Usage



```powershell

powershell.exe -ExecutionPolicy Bypass -File .\\windows\_4688\_triage.ps1 -MaxEvents 300



With custom report path:



powershell.exe -ExecutionPolicy Bypass -File .\\windows\_4688\_triage.ps1 -MaxEvents 300 -ReportPath .\\reports\\soc\_4688\_triage\_report.csv



Output Fields

Time

User

Parent

Process

CommandLine

DecodedCommand

Indicators

Severity

Verdict

Reason

TriageNote



\--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Windows Security Log Triage Script



PowerShell-скрипт для базового SOC-разбора событий Windows Security Log, связанных с созданием процессов.



Основной фокус: \*\*Event ID 4688\*\*.



\## Цель проекта



Скрипт помогает быстро находить подозрительные события запуска процессов в Windows Security Logs.



Он не заменяет полноценный SIEM или EDR, но показывает базовую логику SOC triage:



\- что запустилось;

\- кто запустил;

\- какой был родительский процесс;

\- какая была командная строка;

\- какие подозрительные признаки найдены;

\- насколько событие важно;

\- почему оно отмечено;

\- какой контекст стоит проверить аналитику.



\## Что делает скрипт



Скрипт:



\- читает события \*\*Windows Security Event ID 4688\*\*;

\- вытаскивает ключевые поля:

&#x20; - Time;

&#x20; - User;

&#x20; - Parent Process;

&#x20; - Process;

&#x20; - CommandLine;

\- ищет подозрительные PowerShell-паттерны;

\- ищет high-risk PowerShell-паттерны;

\- ищет discovery-команды;

\- анализирует parent-child цепочки процессов;

\- поддерживает несколько индикаторов на одно событие;

\- добавляет Severity;

\- добавляет Verdict;

\- добавляет Reason;

\- добавляет TriageNote;

\- декодирует PowerShell `EncodedCommand`, если это возможно;

\- экспортирует suspicious-only события в CSV-отчёт.



\## Какие события анализируются



Скрипт работает с Windows Security Log:



```powershell

LogName = Security

Event ID = 4688



Event ID 4688 отвечает за создание нового процесса.



Пример:



Parent:      C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

Process:     C:\\Windows\\System32\\cmd.exe

CommandLine: "C:\\Windows\\System32\\cmd.exe" /c whoami



Такое событие может означать запуск discovery-команды через цепочку:



PowerShell -> cmd.exe -> whoami.exe

Детектируемые индикаторы

PowerShell



Скрипт ищет следующие PowerShell-паттерны:



SUSPICIOUS\_POWERSHELL\_BYPASS

SUSPICIOUS\_POWERSHELL\_NOPROFILE

HIGH\_RISK\_POWERSHELL\_ENCODED

HIGH\_RISK\_HIDDEN\_POWERSHELL



Примеры команд:



powershell.exe -NoProfile

powershell.exe -ExecutionPolicy Bypass

powershell.exe -EncodedCommand <base64>

powershell.exe -WindowStyle Hidden

Discovery-команды



Скрипт ищет базовые команды разведки:



whoami

hostname

ipconfig

systeminfo

nltest

net



Примеры индикаторов:



DISCOVERY\_COMMAND

CMD\_DISCOVERY\_CHAIN

CHILD\_DISCOVERY\_FROM\_CMD

POWERSHELL\_TO\_CMD

Примеры логики

Прямой запуск discovery-команды

Parent:  powershell.exe

Process: whoami.exe



Результат:



Indicators: DISCOVERY\_COMMAND

Severity:   Low

Verdict:    ПОДОЗРИТЕЛЬНО

Reason:     Common discovery command was executed

Discovery через cmd.exe

Parent:      powershell.exe

Process:     cmd.exe

CommandLine: cmd.exe /c whoami



Результат:



Indicators: CMD\_DISCOVERY\_CHAIN, POWERSHELL\_TO\_CMD

Severity:   Medium

Verdict:    ПОДОЗРИТЕЛЬНО

Reason:     cmd.exe executed a discovery command through /c; PowerShell spawned cmd.exe

EncodedCommand

CommandLine: powershell.exe -EncodedCommand <base64>



Результат:



DecodedCmd:  Write-Host SOC\_TEST\_ENCODED

Indicators:  HIGH\_RISK\_POWERSHELL\_ENCODED

Severity:    High

Verdict:     СРОЧНО

Reason:      PowerShell used encoded command execution

TriageNote:  EXPECTED\_LAB\_TEST\_ACTIVITY - generated during SOC training

Severity



Скрипт использует простую систему важности:



Severity	Значение

High	High-risk PowerShell поведение

Medium	Подозрительный PowerShell или shell/discovery цепочка

Low	Базовые discovery-команды

Info	Подозрительный паттерн не найден

Verdict



Скрипт использует три базовых вердикта:



ШУМ

ПОДОЗРИТЕЛЬНО

СРОЧНО



Важно: Severity и Verdict не являются финальным доказательством инцидента.



Например:



Severity: High

Verdict:  СРОЧНО



может означать:



вредоносную активность;

легитимный установщик;

админский скрипт;

EDR/management tool;

учебный тест.



Поэтому в скрипте есть поле TriageNote.



TriageNote



TriageNote добавляет контекст для аналитика.



Примеры:



EXPECTED\_LAB\_TEST\_ACTIVITY - generated during SOC training



Учебная активность, созданная вручную во время SOC-практики.



LIKELY\_LEGIT\_VSCODE\_INSTALLER\_OR\_UPDATE - verify if VS Code install/update was expected



Похоже на легитимный установщик или обновление Visual Studio Code.



TEMP\_PARENT\_WITH\_SUSPICIOUS\_POWERSHELL - review parent file, hash, signature and user activity



PowerShell был запущен из временной директории с подозрительными параметрами. Нужно проверить родительский файл, хэш, подпись и действия пользователя.



HIGH\_RISK\_POWERSHELL - investigate immediately



High-risk PowerShell без дополнительного понятного контекста. Нужно расследовать сразу.



DISCOVERY\_ACTIVITY - correlate with logon events and parent process



Обнаружена discovery-активность. Нужно связать событие с логинами и родительским процессом.



Почему High не всегда инцидент



Скрипт специально не понижает Severity, даже если событие похоже на учебное или легитимное.



Пример:



Indicators: HIGH\_RISK\_POWERSHELL\_ENCODED

Severity:   High

Verdict:    СРОЧНО

TriageNote: EXPECTED\_LAB\_TEST\_ACTIVITY - generated during SOC training



Это значит:



Техника опасная.

Контекст учебный.

Финальный вывод делает аналитик.



Это важная часть SOC-мышления: alert severity не равен final incident severity.



Использование



Запуск скрипта:



powershell.exe -ExecutionPolicy Bypass -File .\\windows\_4688\_triage.ps1



Запуск с увеличенным количеством событий:



powershell.exe -ExecutionPolicy Bypass -File .\\windows\_4688\_triage.ps1 -MaxEvents 300



Запуск с пользовательским путём отчёта:



powershell.exe -ExecutionPolicy Bypass `

&#x20;   -File .\\windows\_4688\_triage.ps1 `

&#x20;   -MaxEvents 300 `

&#x20;   -ReportPath .\\reports\\soc\_4688\_triage\_report.csv

Параметры

Параметр	Описание

MaxEvents	Количество последних событий 4688 для анализа

ReportPath	Путь для сохранения CSV-отчёта

Поля вывода



Скрипт выводит:



Time

User

Parent

Process

CommandLine

DecodedCommand

Indicators

Severity

Verdict

Reason

TriageNote

CSV-отчёт



Скрипт экспортирует найденные подозрительные события в CSV.



Пример пути:



.\\reports\\soc\_4688\_triage\_report.csv



CSV можно открыть в:



Excel;

LibreOffice Calc;

VS Code;

PowerShell;

SIEM-like анализе на следующих этапах.

Пример PowerShell summary



Скрипт показывает сводку по severity:



=== Summary by Severity ===



Name    Count

High    2

Medium  8

Low     2



Также можно группировать по индикаторам:



=== Summary by Indicators ===



Count Name

2     DISCOVERY\_COMMAND

2     CMD\_DISCOVERY\_CHAIN, POWERSHELL\_TO\_CMD

1     HIGH\_RISK\_POWERSHELL\_ENCODED

Ограничения



Скрипт не является полноценным EDR или SIEM.



Он не делает:



проверку хэшей через VirusTotal;

проверку цифровых подписей;

корреляцию с сетевыми событиями;

корреляцию с 4624/4625/4634;

анализ Sysmon;

полноценное MITRE ATT\&CK mapping;

автоматическое подтверждение инцидента.



Это учебный triage-helper для базового анализа Windows Security Logs.



Что можно добавить дальше



Идеи для развития:



корреляция 4688 с 4624 по LogonId;

добавление Sysmon Event ID 1;

добавление Sysmon Event ID 3 для сетевых соединений;

проверка цифровой подписи parent/process файлов;

проверка хэшей;

MITRE ATT\&CK mapping;

HTML-отчёт;

JSON-экспорт;

allowlist для известных легитимных установщиков;

suspicious-only режим;

risk score;

timeline mode.

Учебный вывод



Проект показывает базовую SOC-логику:



Event

\-> Context

\-> Indicators

\-> Severity

\-> Verdict

\-> Reason

\-> TriageNote

\-> Report



Главная идея:



Не каждое подозрительное событие является инцидентом.

Но каждое подозрительное событие требует контекста.



Статус проекта

Версия: v0.8

Текущие возможности:

4688 parsing;

suspicious-only filtering;

PowerShell detection;

discovery detection;

parent-child process analysis;

EncodedCommand decoding;

severity/verdict/reason;

contextual triage notes;

CSV export.




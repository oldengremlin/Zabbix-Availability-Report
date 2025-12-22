#!/usr/bin/env ruby
# encoding: utf-8

=begin
= Zabbix Availability Report

Ruby-скрипт для моніторингу доступності мережевих пристроїв у Zabbix.

== Опис
Скрипт відстежує статус хостів (за ICMP ping або SNMP) та інтерфейсів,
фіксує зміни, проводить аналіз при аваріях і формує звіти на email.

Запускається в cron кожні 5 хвилин, акумулює події та надсилає зведений звіт.

== Особливості
* Підтримка ICMP ping та SNMP як джерела статусу хоста
* Аналіз інтерфейсів тільки при падінні (DOWN)
* Розрахунок часу безаварійної роботи з людяним форматом (українською)
* Звіти на email через +/usr/bin/mail+
* Режими: повний та компактний аналіз
* Запобігання паралельним запускам через +flock+ (рекомендовано)

== Автор
oldengremlin[](https://github.com/oldengremlin)

== Ліцензія
Apache License
Version 2.0, January 2004
=end

require 'net/http'
require 'uri'
require 'json'
require 'optparse'
require 'sqlite3'
require 'fileutils'
require 'time'

# URL Zabbix API
ZABBIX_URL = 'https://z.ukrhub.net/zabbix/api_jsonrpc.php'

# URL Zabbix API
DB_PATH = 'zabbix_status.db'

# Парсер опцій командного рядка
options = {}
OptionParser.new do |opts|
  opts.banner = "Використання: #{$0} -u USER -p PASS [опції]"
  opts.on('-u USER', '--user USER', 'Zabbix user') { |u| options[:user] = u }
  opts.on('-p PASS', '--password PASS', 'Zabbix password') { |p| options[:password] = p }
  opts.on('-d DB', '--db DB', "SQLite БД (за замовч.: #{DB_PATH})") { |d| options[:db] = d }
  opts.on('--show-all', 'Показати поточний стан всіх хостів та інтерфейсів') { options[:show_all] = true }
  opts.on('--since TIME', 'Показати зміни за період (наприклад: 1h, 30m, 2d)') { |t| options[:since] = t }
  opts.on('--show-diff-count', 'Показати кількість змін у підсумку') { options[:diff_count] = true }
  opts.on('--always-update', 'Завжди оновлювати timestamp інтерфейсів (навіть без зміни статусу)') { options[:always_update] = true }
  opts.on('--snmp-status', 'Використовувати SNMP-доступність замість ICMP для статусу хоста') { options[:snmp_status] = true }
  opts.on('--quiet', 'Тихий режим: мінімальний вивід') { options[:quiet] = true }
  opts.on('--analyze-accessibility', 'Аналіз: деталі по інтерфейсах при зміні статусу хоста') { options[:analyze] = true }
  opts.on('--analyze-accessibility-small', 'Компактний аналіз: тільки остання UP/DOWN по інтерфейсах') { options[:analyze_small] = true }
  opts.on('--report-and-flush', 'Надіслати звіт на email і очистити лог') { options[:report_flush] = true }
  opts.on('--report', 'Надіслати звіт на email без очищення логів') { options[:report] = true }
  opts.on('--mail-from EMAIL', 'Від кого (From)') { |e| options[:mail_from] = e }
  opts.on('--mail-to EMAIL', 'Кому (To)') { |e| options[:mail_to] = e }
  opts.on('--mail-replyto EMAIL', 'Reply-To') { |e| options[:mail_replyto] = e }
  opts.on('-h', '--help', 'Допомога') do
    puts opts
    exit
  end
end.parse!

# Валідація опцій
if options[:analyze] && options[:analyze_small]
  warn "Помилка: --analyze-accessibility та --analyze-accessibility-small не можна разом"
  exit 1
end

if (options[:report] || options[:report_flush]) && !(options[:mail_to])
  warn "Для --report або --report-and-flush обов'язково --mail-to"
  exit 1
end

# Авторизація
user     = options[:user]     || ENV['WHOAMI']
password = options[:password] || ENV['WHATISMYPASSWD']
db_path  = options[:db] || DB_PATH

unless user && password
  warn "Вкажіть user/password через -u/-p або WHOAMI/WHATISMYPASSWD"
  exit 1
end

# Парсер --since
since_time = nil
if options[:since]
  if options[:since] =~ /^(\d+)([mhd])$/
    value, unit = $1.to_i, $2
    seconds = case unit
              when 'm' then value * 60
              when 'h' then value * 3600
              when 'd' then value * 86400
              end
    since_time = Time.now.to_i - seconds
  else
    warn "Невірний формат --since (приклади: 30m, 2h, 1d)"
    exit 1
  end
end

# === Підключення до БД ===
FileUtils.mkdir_p(File.dirname(db_path)) if db_path.include?('/')
db = SQLite3::Database.new(db_path)

# Створення таблиць
db.execute_batch <<-SQL
  CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    hardware TEXT
  );
  CREATE TABLE IF NOT EXISTS host_status (
    host_id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    status TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
  );
  CREATE TABLE IF NOT EXISTS interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    UNIQUE(host_id, name),
    FOREIGN KEY(host_id) REFERENCES hosts(id)
  );
  CREATE TABLE IF NOT EXISTS interface_status (
    interface_id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    status TEXT NOT NULL,
    FOREIGN KEY(interface_id) REFERENCES interfaces(id)
  );
  CREATE INDEX IF NOT EXISTS idx_interface_status_ts ON interface_status(timestamp);
  CREATE TABLE IF NOT EXISTS event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    host_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_event_log_ts ON event_log(timestamp);
SQL

# == Клас для роботи з Zabbix API
class ZabbixAPI
  # @param url [String] URL Zabbix API
  # @param user [String] Логін
  # @param password [String] Пароль
  def initialize(url, user, password)
    @uri = URI(url)
    @user = user
    @password = password
    @auth = nil
    @id = 1
  end

  private

  # Виконує JSON-RPC запит
  # @param method [String] Метод API
  # @param params [Hash] Параметри
  # @return [Object] Результат
  def rpc(method, params = {})
    payload = { jsonrpc: '2.0', method: method, params: params, id: (@id += 1) }
    payload[:auth] = @auth if @auth

    http = Net::HTTP.new(@uri.host, @uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    req = Net::HTTP::Post.new(@uri.path, 'Content-Type' => 'application/json')
    req.body = payload.to_json

    res = http.request(req)
    raise "HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)
    json = JSON.parse(res.body)
    raise json['error']['data'] if json['error']
    json['result']
  end

  public

  # Авторизація в Zabbix
  def login
    @auth = rpc('user.login', user: @user, password: @password)
  end

  # Отримує список хостів з snmp_available
  # @return [Array<Hash>]
  def get_current_hosts
    rpc('host.get', {
      output: %w[host name hostid snmp_available],
      selectInventory: ['hardware']
    })
  end

  # Отримує елементи Operational status інтерфейсів
  def get_current_interface_items
    rpc('item.get', {
      output: %w[name lastvalue hostid],
      search: { name: '*Operational status*' },
      searchWildcardsEnabled: true,
      sortfield: 'name'
    })
  end

  # Отримує останнє значення icmpping для хоста
  # @param hostid [String] ID хоста в Zabbix
  # @return [Integer, nil] 1 = UP, 0 = DOWN, nil = немає даних
  def get_icmp_ping_status(hostid)
    # Шукаємо item з key icmpping (або icmpping[*] — Zabbix іноді додає параметри)
    items = rpc('item.get', {
      hostids: hostid,
      search: { key_: 'icmpping' },
      output: ['itemid', 'lastvalue'],
      limit: 1
    })

    return nil if items.empty? || items.first['lastvalue'].nil?

    items.first['lastvalue'].to_i
  end
end

# == Допоміжні методи ==

# Форматує тривалість у людяному вигляді українською
# @param seconds [Integer] Кількість секунд
# @return [String] Наприклад: "2 дні 6 годин 14 хвилин"
def human_duration(seconds)
  return "0 секунд" if seconds <= 0

  parts = []

  years = seconds / (365 * 24 * 3600)
  if years > 0
    parts << "#{years} #{Ukrainian.pluralize(years, 'рік', 'роки', 'років')}"
    seconds %= (365 * 24 * 3600)
  end

  days = seconds / (24 * 3600)
  if days > 0
    parts << "#{days} #{Ukrainian.pluralize(days, 'день', 'дні', 'днів')}"
    seconds %= (24 * 3600)
  end

  hours = seconds / 3600
  if hours > 0
    parts << "#{hours} #{Ukrainian.pluralize(hours, 'година', 'години', 'годин')}"
    seconds %= 3600
  end

  minutes = seconds / 60
  if minutes > 0
    parts << "#{minutes} #{Ukrainian.pluralize(minutes, 'хвилина', 'хвилини', 'хвилин')}"
    seconds %= 60
  end

  if seconds > 0
    parts << "#{seconds} #{Ukrainian.pluralize(seconds, 'секунда', 'секунди', 'секунд')}"
  end

  # Прибираємо останні компоненти, якщо є більші
  # Наприклад: не "2 дні 0 годин 0 хвилин", а просто "2 дні"
  parts = parts.take_while { |p| p !~ /0 (годин|хвилин|секунд)/ }

  case parts.size
  when 0 then "0 секунд"
  when 1 then parts.first
  when 2 then parts.join(' ')
  else
    last = parts.pop
    parts.join(', ') + " та #{last}"
  end
end

module Ukrainian
  # Правильне відмінювання числівників українською
  def self.pluralize(n, one, few, many)
    n = n.abs
    if n % 10 == 1 && n % 100 != 11
      one
    elsif [2,3,4].include?(n % 10) && ![12,13,14].include?(n % 100)
      few
    else
      many
    end
  end
end

# === Основна логіка ===
begin
  api = ZabbixAPI.new(ZABBIX_URL, user, password)
  api.login

  now = Time.now.to_i
  host_changes = 0
  iface_changes = 0
  changed_hosts = []

  puts "Оновлення з Zabbix (#{Time.now.strftime('%Y-%m-%d %H:%M:%S')})" unless options[:quiet]

  current_hosts = api.get_current_hosts
  host_name_to_id = {}
  db.execute("SELECT id, name FROM hosts").each { |r| host_name_to_id[r[1]] = r[0] }
  zabbix_host_map = current_hosts.map { |h| [h['hostid'], h['host']] }.to_h

  # === Хости (тільки ті, що моніторяться по SNMP) ===
  current_hosts.each do |zhost|
    name = zhost['host']
    hostid = zhost['hostid']
    hardware = zhost.dig('inventory', 'hardware') || ''

    snmp_avail = zhost['snmp_available'].to_i
    ping_value = api.get_icmp_ping_status(hostid)

    # Ігноруємо хости без SNMP моніторингу
    next if snmp_avail == 0

    if options[:snmp_status]
      new_status = case snmp_avail
                   when 1 then 'UP'
                   when 2 then 'DOWN'
                   else 'UNKNOWN'
                   end
    else
      new_status = case ping_value
                   when 1 then 'UP'
                   when 0 then 'DOWN'
                   else 'UNKNOWN'
                   end
    end

    unless options[:quiet]
      puts "HOST  #{name.ljust(25)} => #{snmp_avail} #{ping_value} — #{new_status}  @ #{Time.at(now)}"
    end

    # Додаємо/оновлюємо хост в БД
    db.execute("INSERT OR IGNORE INTO hosts (name, hardware) VALUES (?, ?)", [name, hardware])
    db.execute("UPDATE hosts SET hardware = ? WHERE name = ?", [hardware, name]) if hardware != ''

    host_id = db.last_insert_row_id > 0 ? db.last_insert_row_id : host_name_to_id[name]
    host_id ||= db.get_first_value("SELECT id FROM hosts WHERE name = ?", name)

    # Перевіряємо зміну статусу
    prev = db.get_first_row("SELECT status FROM host_status WHERE host_id = ?", host_id)
    prev_status = prev&.first

    if prev_status != new_status
     # db.execute("INSERT OR REPLACE INTO host_status (host_id, timestamp, status) VALUES (?, ?, ?)", [host_id, now, new_status])
      db.execute("UPDATE host_status SET timestamp = ?, status = ? WHERE host_id = ?", [now, new_status, host_id])
      # Якщо рядка ще немає (новий хост) — треба INSERT
      if db.changes == 0
        db.execute("INSERT INTO host_status (host_id, timestamp, status) VALUES (?, ?, ?)", [host_id, now, new_status])
      end
      host_changes += 1
      changed_hosts << { name: name, host_id: host_id, old: prev_status, new: new_status, ts: now }

      unless options[:quiet]
        change = prev_status ? "(#{prev_status} → #{new_status})" : "(новий)"
        puts "HOST  #{name.ljust(25)} => #{new_status} #{change}  @ #{Time.at(now)}"
      end
    end
  end

  # === Інтерфейси ===
  items = api.get_current_interface_items
  items.each do |item|
    next unless item['lastvalue']

    z_hostid = item['hostid']
    host_name = zabbix_host_map[z_hostid] || next
    iface_full = item['name'].sub(/:?\s*Operational status.*$/i, '').strip
    new_status = item['lastvalue'].to_i == 1 ? 'UP' : 'DOWN'

    host_id = host_name_to_id[host_name] || db.get_first_value("SELECT id FROM hosts WHERE name = ?", host_name)
    next unless host_id

    db.execute("INSERT OR IGNORE INTO interfaces (host_id, name) VALUES (?, ?)", [host_id, iface_full])
    iface_id = db.last_insert_row_id > 0 ? db.last_insert_row_id : db.get_first_value("SELECT id FROM interfaces WHERE host_id = ? AND name = ?", [host_id, iface_full])

    prev = db.get_first_row("SELECT status FROM interface_status WHERE interface_id = ?", iface_id)
    prev_status = prev&.first

    if options[:always_update] or prev_status != new_status
     # db.execute("INSERT OR REPLACE INTO interface_status (interface_id, timestamp, status) VALUES (?, ?, ?)", [iface_id, now, new_status])
      db.execute("UPDATE interface_status SET timestamp = ?, status = ? WHERE interface_id = ?", [now, new_status, iface_id])
      if db.changes == 0  # рядка ще не було (новий інтерфейс)
        db.execute("INSERT INTO interface_status (interface_id, timestamp, status) VALUES (?, ?, ?)", [iface_id, now, new_status])
      end
      iface_changes += 1

      unless options[:quiet]
        change = prev_status ? "(#{prev_status} → #{new_status})" : "(новий)"
        puts "IFACE #{host_name.ljust(20)} | #{iface_full.ljust(50)} => #{new_status} #{change}  @ #{Time.at(now)}"
      end
    end
  end

  # === Аналіз доступності ===
  if options[:analyze] || options[:analyze_small]
    changed_hosts.each do |ch|
      host_name = ch[:name]
      host_id = ch[:host_id]
      host_ts = Time.at(ch[:ts])
      old_status = ch[:old]
      new_status = ch[:new]
      report_lines = []
      event_type = new_status == 'DOWN' ? 'HOST_DOWN' : 'HOST_UP'

      # Повідомляємо про будь-яку зміну хоста
      change = old_status ? "(#{old_status} → #{new_status})" : "(новий)"
      # report_lines << "\n#{'=' * 80}"
      # report_lines << "\nHOST #{host_name.ljust(25)} => #{new_status} #{change} @ #{host_ts.strftime('%Y-%m-%d %H:%M:%S')}"

      # АНАЛІЗ ТІЛЬКИ ПРИ ПАДІННІ (новий статус DOWN)
      if new_status == 'DOWN'

        up_ts = db.get_first_value("SELECT MAX(timestamp) FROM event_log WHERE host_name = ? AND event_type = 'HOST_UP' AND timestamp < ?", [host_name, ch[:ts]])
        up_ts ||= 0 # якщо немає попереднього UP — показуємо всі зміни

        report_lines << "\n#{'=' * 80}"
        report_lines << "АВАРІЯ: #{host_name} — #{host_ts.strftime('%Y-%m-%d %H:%M:%S')}"

        if up_ts == 0
          report_lines << "        Попередній стан UP не зафіксовано (перша аварія або очищений лог)"
        else
          duration_seconds = ch[:ts] - up_ts
          duration_human = human_duration(duration_seconds)
          report_lines << "        Час безаварійної роботи: #{duration_human}"
          report_lines << "        (з #{Time.at(up_ts).strftime('%Y-%m-%d %H:%M:%S')} по #{host_ts.strftime('%Y-%m-%d %H:%M:%S')})"
        end

        report_lines << "#{'=' * 80}"

        if options[:analyze_small]
          # Компактний аналіз — тільки остання UP та DOWN по інтерфейсах
          last_up = db.get_first_row(<<-SQL, [host_id, up_ts, ch[:ts]])
            SELECT i.name, datetime(ifs.timestamp, 'unixepoch', 'localtime')
            FROM interface_status ifs
            JOIN interfaces i ON ifs.interface_id = i.id
            WHERE i.host_id = ? AND ifs.status = 'UP' AND ifs.timestamp > ? AND ifs.timestamp <= ?
            ORDER BY ifs.timestamp DESC LIMIT 1
          SQL
          last_down = db.get_first_row(<<-SQL, [host_id, up_ts, ch[:ts]])
            SELECT i.name, datetime(ifs.timestamp, 'unixepoch', 'localtime')
            FROM interface_status ifs
            JOIN interfaces i ON ifs.interface_id = i.id
            WHERE i.host_id = ? AND ifs.status = 'DOWN' AND ifs.timestamp > ? AND ifs.timestamp <= ?
            ORDER BY ifs.timestamp DESC LIMIT 1
          SQL
          report_lines << "Остання UP зміна: #{last_up ? "#{last_up[0]} о #{last_up[1]}" : 'немає даних'}"
          report_lines << "Остання DOWN зміна: #{last_down ? "#{last_down[0]} о #{last_down[1]}" : 'немає даних'}"
        else
          # Повний аналіз — зміни інтерфейсів між UP і DOWN
          report_lines << "Зміни на інтерфейсах між останнім UP та DOWN (від свіжих до старих):"
          report_lines << " Час останньої зміни → Статус | Інтерфейс"
          report_lines << " #{'-' * 77}"
          count = 0
          db.execute(<<-SQL, [host_id, up_ts, ch[:ts]]).each do |row|
            SELECT i.name, ifs.status, datetime(ifs.timestamp, 'unixepoch', 'localtime')
            FROM interface_status ifs
            JOIN interfaces i ON ifs.interface_id = i.id
            WHERE i.host_id = ? AND ifs.timestamp > ? AND ifs.timestamp <= ?
            ORDER BY ifs.timestamp DESC, ifs.status, i.name
            LIMIT 30
          SQL
            count += 1
            report_lines << " #{row[2]} → #{row[1].ljust(6)} | #{row[0]}"
          end
          report_lines << " (показано #{count} #{Ukrainian.pluralize(count, 'зміна', 'зміни', 'змін')})" if count > 0
          report_lines << " (немає змін у цьому інтервалі)" if count == 0
        end
      else
        report_lines << "\n#{'=' * 80}"
        report_lines << "ВІДНОВЛЕННЯ: #{host_name} — #{host_ts.strftime('%Y-%m-%d %H:%M:%S')}"
        report_lines << "#{'=' * 80}"
      end
      details = report_lines.join("\n")
      db.execute("INSERT INTO event_log (timestamp, host_name, event_type, details) VALUES (?, ?, ?, ?)", [ch[:ts], host_name, event_type, details])
      unless options[:quiet]
        puts details
      end
    end
  else
    unless options[:quiet]
      # Якщо аналіз не ввімкнено — просто виводимо зміни хостів (як і раніше)
      changed_hosts.each do |ch|
        host_name = ch[:name]
        host_ts = Time.at(ch[:ts])
        old_status = ch[:old]
        new_status = ch[:new]
        change = old_status ? "(#{old_status} → #{new_status})" : "(новий)"
        puts "HOST #{host_name.ljust(25)} => #{new_status} #{change} @ #{host_ts.strftime('%Y-%m-%d %H:%M:%S')}"
      end
    end
  end

  # === Звіт ===
  if options[:report] || options[:report_flush]
    events = db.execute("SELECT timestamp, host_name, event_type, details FROM event_log ORDER BY timestamp ASC")
    if events.empty?
      puts "Немає подій для звіту." unless options[:quiet]
      exit 0
    end
    report = []
    report << "Звіт про доступність мережі"
    report << "Період: #{Time.at(events.first[0]).strftime('%Y-%m-%d %H:%M')} — #{Time.at(events.last[0]).strftime('%Y-%m-%d %H:%M')}"
    # report << ""
    # report << "=" * 80
    # report << ""
    events.each do |ev|
      # report << "[#{Time.at(ev[0]).strftime('%Y-%m-%d %H:%M:%S')}] #{ev[2]}: #{ev[1]}"
      report << ev[3]
      report << "-" * 80
    end
    body = report.join("\n")
    subject = "Zabbix Availability Report — #{Time.now.strftime('%Y-%m-%d')}"
    cmd = %w[/usr/bin/mail -s]
    cmd << subject
    cmd << "-r" << options[:mail_from] if options[:mail_from]
    cmd << "-r" << options[:mail_replyto] if options[:mail_replyto]
    cmd << options[:mail_to]
    IO.popen(cmd, 'w') do |mail|
      mail.puts body
    end
    if $?.success?
      puts "Звіт надіслано на #{options[:mail_to]}" unless options[:quiet]
      db.execute("DELETE FROM event_log") if options[:report_flush]
    else
      warn "Помилка надсилання листа!"
      exit 1
    end
  end

  # === Вивід ===
  if options[:show_all] && !options[:quiet]
    puts "\n=== Поточний стан хостів (SNMP) ==="
    db.execute(<<-SQL).each do |row|
      SELECT h.name, hs.status, datetime(hs.timestamp, 'unixepoch', 'localtime')
      FROM host_status hs JOIN hosts h ON hs.host_id = h.id
      ORDER BY h.name
    SQL
      puts "#{row[0].ljust(25)} => #{row[1]} (з #{row[2]})"
    end

    puts "\n=== Поточний стан інтерфейсів ==="
    db.execute(<<-SQL).each do |row|
      SELECT h.name, i.name, ifs.status, datetime(ifs.timestamp, 'unixepoch', 'localtime')
      FROM interface_status ifs JOIN interfaces i ON ifs.interface_id = i.id JOIN hosts h ON i.host_id = h.id
      ORDER BY h.name, i.name
    SQL
      puts "#{row[0].ljust(20)} | #{row[1].ljust(50)} => #{row[2]} (з #{row[3]})"
    end
  end

  if since_time && !options[:quiet]
    puts "\n=== Зміни за останні #{options[:since]} ==="
    db.execute(<<-SQL, [since_time, since_time]).each do |row|
      SELECT 'HOST', h.name, '', hs.status, datetime(hs.timestamp, 'unixepoch', 'localtime')
      FROM host_status hs JOIN hosts h ON hs.host_id = h.id WHERE hs.timestamp >= ?
      UNION ALL
      SELECT 'IFACE', h.name, i.name, ifs.status, datetime(ifs.timestamp, 'unixepoch', 'localtime')
      FROM interface_status ifs JOIN interfaces i ON ifs.interface_id = i.id JOIN hosts h ON i.host_id = h.id
      WHERE ifs.timestamp >= ?
      ORDER BY 5 DESC
    SQL
      if row[0] == 'HOST'
        puts "HOST  #{row[1].ljust(25)} => #{row[3]}  @ #{row[4]}"
      else
        puts "IFACE #{row[1].ljust(20)} | #{row[2].ljust(50)} => #{row[3]}  @ #{row[4]}"
      end
    end
  end

  if (options[:diff_count] || host_changes + iface_changes > 0) && !options[:quiet]
    puts "\nПідсумок:"
    puts "  Змін хостів:     #{host_changes}"
    puts "  Змін інтерфейсів: #{iface_changes}"
    puts "  Всього змін:     #{host_changes + iface_changes}"
  end

  puts "Готово! Дані в #{db_path}" unless options[:quiet]

rescue => e
  warn "Помилка: #{e.message}"
  warn e.backtrace.join("\n")
  exit 1
ensure
  db&.close
end

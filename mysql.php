<?php
/**
 * Nodeewa 数据库管理工具 —— 安全优化版
 * ------------------------------------------------------------
 * 基于原版 mysql_manager.php 的修复与优化版本，功能与原版保持一致：
 *   - 数据库登录 / 切换 / 表列表 / 表结构 / 数据分页浏览
 *   - 新增 / 编辑 / 删除记录（全部改为预编译语句）
 *   - SQL 控制台（多语句执行，首词白名单 + 高危关键字黑名单双重校验）
 *   - SQL 文件导入 / 单表 SQL 导出
 *
 * 运行环境：PHP >= 8.0（原版已使用 str_contains 等 PHP 8 特性）
 * 安全声明：本工具用于管理数据库，仅应部署于可信内网环境，
 *   并建议为其配置独立的最小权限数据库账号。
 * ------------------------------------------------------------
 */

declare(strict_types=1);

/* ===================== 配置区 ===================== */
const APP_ENV             = 'prod';               // 'dev' 显示错误详情；'prod' 隐藏并只写日志
const DB_HOST_WHITELIST   = [];                   // 允许连接的主机白名单，如 ['localhost','127.0.0.1']；空数组=不限制（不推荐用于公网）
const SQL_MAX_LENGTH      = 1024 * 1024;          // 单次 SQL 最大字节数（1MB）
const SQL_RESULT_MAX_ROWS = 1000;                 // 单条 SQL 结果显示的最大行数，防止内存/页面被打爆
const LOGIN_MAX_ATTEMPTS  = 5;                    // 登录失败锁定阈值（0=关闭限流）
const LOGIN_LOCK_MINUTES  = 10;                   // 锁定窗口（分钟）

/* ===================== 错误显示控制 ===================== */
error_reporting(E_ALL);
ini_set('display_errors', APP_ENV === 'dev' ? '1' : '0');
ini_set('display_startup_errors', APP_ENV === 'dev' ? '1' : '0');
ini_set('log_errors', '1');

/* ===================== 会话与安全响应头 ===================== */
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    ]);
    session_start();
}
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'");

/* ===================== CSRF ===================== */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
function csrfToken(): string
{
    return (string)($_SESSION['csrf_token'] ?? '');
}
function checkCsrf(): bool
{
    $token = $_POST['csrf'] ?? '';
    return is_string($token) && $token !== '' && hash_equals(csrfToken(), $token);
}
/** HTML 输出转义（ENT_QUOTES，同时转义单双引号，兼容 PHP 8.0 与 8.1+） */
function h($s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
/** 构造可安全内嵌到 HTML 属性中、用单引号包裹的 JS 字符串字面量 */
function jsq(string $s): string
{
    return "'" . str_replace(['\\', "'"], ['\\\\', "\\'"], $s) . "'";
}

/* ===================== 登录限流（按 IP 的文件计数） ===================== */
function throttleFile(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'nodeewa_login_' . md5($ip) . '.lock';
}
function checkThrottle(): void
{
    if (LOGIN_MAX_ATTEMPTS <= 0) return;
    $file = throttleFile();
    $data = null;
    if (is_file($file)) {
        $content = @file_get_contents($file);
        $data = $content ? json_decode($content, true) : null;
    }
    $now = time();
    $attempts = is_array($data) ? (int)($data['count'] ?? 0) : 0;
    $first    = is_array($data) ? (int)($data['first'] ?? $now) : $now;
    $window   = LOGIN_LOCK_MINUTES * 60;
    if ($attempts >= LOGIN_MAX_ATTEMPTS && ($now - $first) < $window) {
        $remain = (int)ceil(($first + $window - $now) / 60);
        throw new RuntimeException("登录尝试次数过多，请 {$remain} 分钟后再试");
    }
}
function recordFailure(): void
{
    if (LOGIN_MAX_ATTEMPTS <= 0) return;
    $file = throttleFile();
    $now  = time();
    $window = LOGIN_LOCK_MINUTES * 60;
    $data = null;
    if (is_file($file)) {
        $content = @file_get_contents($file);
        $data = $content ? json_decode($content, true) : null;
    }
    $attempts = is_array($data) ? (int)($data['count'] ?? 0) : 0;
    $first    = is_array($data) ? (int)($data['first'] ?? $now) : $now;
    if (($now - $first) >= $window) { $attempts = 0; $first = $now; }
    $attempts++;
    @file_put_contents($file, json_encode(['count' => $attempts, 'first' => $first]));
}
function clearThrottle(): void
{
    @unlink(throttleFile());
}
/** 主机白名单校验，防止把服务器变成内网 MySQL 扫描/爆破代理 */
function guardHost(string $host): void
{
    if (DB_HOST_WHITELIST === []) return;
    $h = strtolower(trim($host));
    if (!in_array($h, array_map('strtolower', DB_HOST_WHITELIST), true)) {
        throw new RuntimeException('该数据库主机不在允许访问的白名单内');
    }
}

/* ===================== 数据库连接类 ===================== */
class DBManager
{
    private ?mysqli $conn = null;
    private string $host;
    private string $user;
    private string $pass;
    private string $dbname;
    private array $structureCache = [];

    public function __construct(string $host, string $user, string $pass, string $dbname = '')
    {
        $this->host   = $host;
        $this->user   = $user;
        $this->pass   = $pass;
        $this->dbname = $dbname;
    }

    public function connect(): self
    {
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $conn = mysqli_init();
        if (!$conn) {
            throw new RuntimeException('无法初始化 MySQL 驱动');
        }
        // 连接超时必须设置在 real_connect 之前才生效（原版设置在连接之后，是无效代码）
        $conn->options(MYSQLI_OPT_CONNECT_TIMEOUT, 5);
        try {
            $conn->real_connect($this->host, $this->user, $this->pass);
        } catch (mysqli_sql_exception $e) {
            throw new RuntimeException('数据库连接失败，请核对账号密码地址');
        }
        $conn->set_charset('utf8mb4');
        $this->conn = $conn;
        if ($this->dbname !== '') {
            $this->selectDb($this->dbname);
        }
        return $this;
    }

    public function selectDb(string $dbName): bool
    {
        $this->conn?->select_db($dbName);
        $this->dbname = $dbName;
        return true;
    }

    public function getConn(): mysqli
    {
        if (!$this->conn) {
            throw new RuntimeException('数据库未连接');
        }
        return $this->conn;
    }

    public function getCurrentDatabase(): string
    {
        $res  = $this->conn->query('SELECT DATABASE() AS now_db');
        $row  = $res->fetch_assoc();
        return (string)($row['now_db'] ?? '');
    }

    /* ---------- 标识符校验（表名/库名/字段名） ---------- */
    public static function validateDbName(string $name): bool
    {
        return $name !== '' && preg_match('/^[A-Za-z0-9_]+$/', $name) === 1;
    }
    public static function validateTableName(string $name): bool
    {
        return $name !== '' && strlen($name) <= 64 && preg_match('/^[A-Za-z0-9_]+$/', $name) === 1;
    }
    /** 字段名：禁止反引号与空字节，支持中文等合法 MySQL 字段 */
    public static function validateColumnName(string $name): bool
    {
        return $name !== '' && strlen($name) <= 128 && !str_contains($name, '`') && !str_contains($name, "\0");
    }

    private function guardTable(string $table): void
    {
        if (!self::validateTableName($table)) {
            throw new RuntimeException('非法表名');
        }
    }

    /* ---------- 查询方法（严格模式：SQL 失败会抛 mysqli_sql_exception） ---------- */
    public function getDatabases(): array
    {
        $result = $this->conn->query('SHOW DATABASES');
        return $result->fetch_all(MYSQLI_ASSOC);
    }

    public function getTables(): array
    {
        $result = $this->conn->query('SHOW TABLES');
        $raw    = $result->fetch_all(MYSQLI_NUM);
        $out    = [];
        foreach ($raw as $row) {
            $out[] = ['TableName' => $row[0]];
        }
        return $out;
    }

    /** 表结构（带请求内缓存，避免同一请求内 DESCRIBE 反复执行） */
    public function getTableStructure(string $table): array
    {
        $this->guardTable($table);
        if (isset($this->structureCache[$table])) {
            return $this->structureCache[$table];
        }
        $result = $this->conn->query("DESCRIBE `$table`");
        $this->structureCache[$table] = $result->fetch_all(MYSQLI_ASSOC);
        return $this->structureCache[$table];
    }

    public function dropTable(string $table): bool
    {
        $this->guardTable($table);
        return $this->conn->query("DROP TABLE `$table`");
    }

    public function getTableDataCount(string $table): int
    {
        $this->guardTable($table);
        $result = $this->conn->query("SELECT COUNT(*) AS total FROM `$table`");
        $row    = $result->fetch_assoc();
        return (int)($row['total'] ?? 0);
    }

    public function getTableData(string $table, int $page = 1, int $limit = 20): array
    {
        $this->guardTable($table);
        $page   = max(1, $page);
        $limit  = max(1, min(100, $limit));
        $offset = ($page - 1) * $limit;
        $result = $this->conn->query("SELECT * FROM `$table` LIMIT $offset, $limit");
        return $result->fetch_all(MYSQLI_ASSOC);
    }

    /* ---------- 行级操作（全部使用预编译语句，杜绝拼接注入） ---------- */
    public function getTableRow(string $table, int|string $id, string $primaryKey): ?array
    {
        $this->guardTable($table);
        if (!self::validateColumnName($primaryKey)) {
            throw new RuntimeException('非法主键字段');
        }
        $stmt = $this->conn->prepare("SELECT * FROM `$table` WHERE `$primaryKey` = ? LIMIT 1");
        $stmt->bind_param('s', (string)$id);
        $stmt->execute();
        $res = $stmt->get_result();
        return $res->fetch_assoc() ?: null;
    }

    public function updateTableRow(string $table, array $data, string $primaryKey, int|string $id): bool
    {
        $this->guardTable($table);
        if (!self::validateColumnName($primaryKey)) {
            throw new RuntimeException('非法主键字段');
        }
        $set   = [];
        $types = '';
        $vals  = [];
        foreach ($data as $key => $value) {
            if (!is_string($key) || $key === $primaryKey || !self::validateColumnName($key)) {
                continue;
            }
            $set[]   = "`$key` = ?";
            $types  .= 's';
            $vals[]  = (string)$value;
        }
        if ($set === []) {
            return false;
        }
        $types .= 's';
        $vals[] = (string)$id;
        $stmt   = $this->conn->prepare("UPDATE `$table` SET " . implode(', ', $set) . " WHERE `$primaryKey` = ?");
        $stmt->bind_param($types, ...$vals);
        return $stmt->execute();
    }

    public function deleteTableRow(string $table, string $primaryKey, int|string $id): bool
    {
        $this->guardTable($table);
        if (!self::validateColumnName($primaryKey)) {
            throw new RuntimeException('非法主键字段');
        }
        $stmt = $this->conn->prepare("DELETE FROM `$table` WHERE `$primaryKey` = ?");
        $stmt->bind_param('s', (string)$id);
        return $stmt->execute();
    }

    public function insertTableRow(string $table, array $data): bool
    {
        $this->guardTable($table);
        $cols  = [];
        $types = '';
        $vals  = [];
        foreach ($data as $key => $value) {
            if (!is_string($key) || !self::validateColumnName($key)) {
                continue;
            }
            $cols[]  = "`$key`";
            $types  .= 's';
            $vals[]  = (string)$value;
        }
        if ($cols === []) {
            return false;
        }
        $placeholders = implode(', ', array_fill(0, count($cols), '?'));
        $stmt = $this->conn->prepare("INSERT INTO `$table` (" . implode(', ', $cols) . ") VALUES ($placeholders)");
        $stmt->bind_param($types, ...$vals);
        return $stmt->execute();
    }

    public function getPrimaryKey(string $table): ?string
    {
        foreach ($this->getTableStructure($table) as $row) {
            if (($row['Key'] ?? '') === 'PRI') {
                return (string)$row['Field'];
            }
        }
        return null;
    }

    /* ---------- 任意 SQL 执行（多语句，白名单+黑名单双重防护） ---------- */

    /** 语句切分：只按“引号/注释之外的顶层分号”切分，避免字符串内的分号误切 */
    private function splitStatements(string $sql): array
    {
        $statements = [];
        $len  = strlen($sql);
        $cur  = '';
        $quote = null; // null | "'" | '"' | '`'
        $i = 0;
        while ($i < $len) {
            $ch   = $sql[$i];
            $next = $i + 1 < $len ? $sql[$i + 1] : '';
            if ($quote !== null) {
                $cur .= $ch;
                if ($ch === '\\' && $i + 1 < $len) {
                    $cur .= $sql[$i + 1];
                    $i += 2;
                    continue;
                }
                if ($ch === '`' && $next === '`') { // 反引号内 `` 转义
                    $cur .= $next;
                    $i += 2;
                    continue;
                }
                if ($ch === $quote) {
                    $quote = null;
                }
                $i++;
                continue;
            }
            if ($ch === "'" || $ch === '"' || $ch === '`') {
                $quote = $ch;
                $cur  .= $ch;
                $i++;
                continue;
            }
            if ($ch === '-' && $next === '-') { // -- 行注释（MySQL 要求后随空白或行尾）
                $third = $i + 2 < $len ? $sql[$i + 2] : '';
                if ($third === '' || $third === ' ' || $third === "\t" || $third === "\n" || $third === "\r") {
                    while ($i < $len && $sql[$i] !== "\n") {
                        $cur .= $sql[$i];
                        $i++;
                    }
                    continue;
                }
            }
            if ($ch === '#') {
                while ($i < $len && $sql[$i] !== "\n") {
                    $cur .= $sql[$i];
                    $i++;
                }
                continue;
            }
            if ($ch === '/' && $next === '*') { // 块注释（含版本化注释 /*! ... */）
                $cur .= '/*';
                $i += 2;
                while ($i < $len && !($sql[$i] === '*' && $i + 1 < $len && $sql[$i + 1] === '/')) {
                    $cur .= $sql[$i];
                    $i++;
                }
                if ($i + 1 < $len) {
                    $cur .= '*/';
                    $i += 2;
                }
                continue;
            }
            if ($ch === ';') {
                $statements[] = trim($cur);
                $cur = '';
                $i++;
                continue;
            }
            $cur .= $ch;
            $i++;
        }
        if (trim($cur) !== '') {
            $statements[] = trim($cur);
        }
        return $statements;
    }

    /** 仅用于检测：去掉注释（不影响真实执行的原语句） */
    private function stripComments(string $sql): string
    {
        $sql = preg_replace('/\/\*.*?\*\//s', ' ', $sql) ?? $sql;
        $sql = preg_replace('/--[ \t\r\n][^\r\n]*/', ' ', $sql) ?? $sql;
        $sql = preg_replace('/#[^\r\n]*/', ' ', $sql) ?? $sql;
        return $sql;
    }

    /** 仅用于检测：把字符串/标识符字面量替换为空格，避免数据内容触发黑名单误报 */
    private function stripStrings(string $sql): string
    {
        $out   = '';
        $len   = strlen($sql);
        $quote = null;
        for ($i = 0; $i < $len; $i++) {
            $ch = $sql[$i];
            if ($quote !== null) {
                if ($ch === '\\' && $i + 1 < $len) {
                    $i++;
                    continue;
                }
                if ($ch === $quote) {
                    $quote = null;
                }
                $out .= ' ';
                continue;
            }
            if ($ch === "'" || $ch === '"' || $ch === '`') {
                $quote = $ch;
                $out  .= ' ';
                continue;
            }
            $out .= $ch;
        }
        return $out;
    }

    /**
     * 单语句防护：首词白名单 + 高危关键字黑名单（词边界匹配）。
     * 白名单兜底解决“黑名单可被注释/大小写绕过”的问题；
     * 黑名单在去注释、去字符串后的文本上做 \b 词边界匹配，同时避免误伤列名（如 created_at）。
     */
    private function guardStatement(string $stmt): void
    {
        $plain = $this->stripComments($stmt);
        if (!preg_match('/^\s*([A-Za-z]+)/', $plain, $m)) {
            throw new RuntimeException('无法识别 SQL 语句类型，已拦截');
        }
        $first = strtolower($m[1]);
        $allowed = [
            'select', 'show', 'describe', 'desc', 'explain', 'set', 'use',
            'insert', 'update', 'delete', 'replace',
            'start', 'commit', 'rollback', 'begin', 'with',
        ];
        if (!in_array($first, $allowed, true)) {
            throw new RuntimeException('已拦截：仅允许 SELECT/SHOW/INSERT/UPDATE/DELETE 等语句（当前语句类型: ' . strtoupper($first) . '）');
        }
        $detect = strtolower($this->stripStrings($plain));
        // 只读语句类型（SHOW/DESCRIBE/EXPLAIN）无执行风险，跳过黑名单检查，从而允许 SHOW CREATE TABLE 等只读用法
        $readOnlyFirst = in_array($first, ['show', 'describe', 'desc', 'explain'], true);
        if (!$readOnlyFirst) {
            $black  = '/\b(drop|alter|truncate|create|rename|grant|revoke|outfile|dumpfile|infile|load_file|sleep|benchmark|lock|unlock|kill|shutdown|super|master|slave|handler|call|prepare|execute|xa|attach|detach|flush|reset|optimize|repair|analyze|binlog)\b/';
            if (preg_match($black, $detect, $bm)) {
                throw new RuntimeException('拦截高危语句：禁止包含 ' . strtoupper($bm[1]));
            }
        }
    }

    /** 执行任意 SQL（多语句）。返回结构化结果；高危语句会在执行前被拦截并抛异常。 */
    public function executeSql(string $sql): array
    {
        $sql = trim($sql);
        if ($sql === '') {
            return [];
        }
        if (strlen($sql) > SQL_MAX_LENGTH) {
            throw new RuntimeException('SQL 语句过长，超出单次执行上限');
        }
        foreach ($this->splitStatements($sql) as $stmt) {
            if (trim($stmt) === '') {
                continue;
            }
            $this->guardStatement($stmt);
        }

        $output = [];
        $this->conn->multi_query($sql);
        do {
            if ($result = $this->conn->store_result()) {
                $fields = $this->getFieldNames($result);
                $total  = $result->num_rows;
                $rows   = [];
                $n      = 0;
                while ($n < SQL_RESULT_MAX_ROWS && ($row = $result->fetch_assoc())) {
                    $rows[] = $row;
                    $n++;
                }
                $result->free();
                $item = ['type' => 'result', 'data' => $rows, 'fields' => $fields];
                if ($total > $n) {
                    $item['truncated'] = true;
                    $item['total']     = $total;
                }
                $output[] = $item;
            } else {
                $output[] = ['type' => 'info', 'message' => '受影响行数: ' . $this->conn->affected_rows];
            }
        } while ($this->conn->more_results() && $this->conn->next_result());
        return $output;
    }

    private function getFieldNames(mysqli_result $result): array
    {
        $fields = [];
        while ($field = $result->fetch_field()) {
            $fields[] = $field->name;
        }
        return $fields;
    }

    /** 导出单表：建表语句 + 全部数据 INSERT（流式输出，不依赖服务器 mysqldump） */
    public function exportSql(string $table): void
    {
        $this->guardTable($table);
        $create = $this->conn->query("SHOW CREATE TABLE `$table`");
        $row    = $create->fetch_assoc();
        $createSql = (string)($row['Create Table'] ?? '');

        echo "-- Nodeewa 数据库工具导出（安全优化版）\n";
        echo "-- 数据库: " . $this->getCurrentDatabase() . "\n";
        echo "-- 表: `{$table}`\n";
        echo "-- 时间: " . date('Y-m-d H:i:s') . "\n\n";
        echo "SET NAMES utf8mb4;\n";
        echo "SET FOREIGN_KEY_CHECKS = 0;\n\n";
        echo $createSql . ";\n\n";

        $res = $this->conn->query("SELECT * FROM `$table`");
        while ($rowData = $res->fetch_assoc()) {
            $cols = [];
            $vals = [];
            foreach ($rowData as $col => $v) {
                $cols[] = '`' . str_replace('`', '``', (string)$col) . '`';
                if ($v === null) {
                    $vals[] = 'NULL';
                } else {
                    $vals[] = "'" . $this->conn->real_escape_string((string)$v) . "'";
                }
            }
            echo "INSERT INTO `$table` (" . implode(', ', $cols) . ") VALUES (" . implode(', ', $vals) . ");\n";
        }
        echo "\nSET FOREIGN_KEY_CHECKS = 1;\n";
    }

    public function close(): void
    {
        if ($this->conn instanceof mysqli) {
            try {
                $this->conn->close();
            } catch (Exception $e) {
                error_log('关闭连接异常: ' . substr((string)$e->getMessage(), 0, 500));
            }
            $this->conn = null;
        }
    }
}

/* ===================== 请求处理 ===================== */
$validActions = [
    'login', 'tables', 'view_table', 'view_structure', 'sql', 'execute_sql',
    'drop_table', 'update_row', 'delete_row', 'insert_row',
    'export_sql', 'import_sql', 'change_db', 'logout',
];
$action = (string)($_REQUEST['action'] ?? 'login');
if (!in_array($action, $validActions, true)) {
    $action = 'tables';
}
$message = ['type' => '', 'text' => ''];
$db = null;
$execResult = [];

/** 单连接复用：同一请求内所有操作共用一个数据库连接 */
function getDb(): DBManager
{
    global $db;
    if ($db instanceof DBManager) {
        return $db;
    }
    $db = (new DBManager(...array_values($_SESSION['db_config'])))->connect();
    return $db;
}

/** 过滤行数据：只保留表结构中真实存在的字段，剔除 csrf/redirect/id 等元字段（修复原版“csrf 字段被写入 SQL 导致新增/编辑必然失败”的缺陷） */
function filterRowData(DBManager $db, string $table, array $input): array
{
    $allowed = [];
    foreach ($db->getTableStructure($table) as $f) {
        $allowed[(string)$f['Field']] = true;
    }
    $out = [];
    foreach ($input as $k => $v) {
        if (!is_string($k) || in_array($k, ['csrf', 'redirect', 'id'], true)) {
            continue;
        }
        if (isset($allowed[$k])) {
            $out[$k] = $v;
        }
    }
    return $out;
}

/* ---------- 登录（原版缺 CSRF 校验与限流，此处补齐） ---------- */
if ($action === 'login' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    try {
        if (!checkCsrf()) {
            throw new RuntimeException('安全校验失败，请刷新页面后重试');
        }
        $host   = trim((string)($_POST['host'] ?? ''));
        $user   = trim((string)($_POST['user'] ?? ''));
        $pass   = (string)($_POST['pass'] ?? '');
        $dbname = trim((string)($_POST['dbname'] ?? ''));
        if ($host === '' || $user === '') {
            throw new RuntimeException('主机与用户名不能为空');
        }
        guardHost($host);
        checkThrottle();
        try {
            $db = (new DBManager($host, $user, $pass))->connect();
        } catch (Exception $e) {
            recordFailure();
            throw new RuntimeException('数据库登录失败，请核对账号密码地址');
        }
        if ($dbname !== '') {
            if (!DBManager::validateDbName($dbname)) {
                throw new RuntimeException('非法数据库名称');
            }
            $db->selectDb($dbname);
        }
        clearThrottle();
        session_regenerate_id(true); // 防会话固定
        $_SESSION['db_config'] = ['host' => $host, 'user' => $user, 'pass' => $pass, 'dbname' => $dbname];
        header('Location: ?action=tables');
        exit;
    } catch (Exception $e) {
        error_log('登录异常: ' . substr((string)$e->getMessage(), 0, 500));
        $message = ['type' => 'error', 'text' => $e->getMessage()];
    }
}

/* ---------- 切换数据库（原版为 GET 且无 CSRF，此处改为 POST + CSRF） ---------- */
if ($action === 'change_db' && isset($_SESSION['db_config']) && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!checkCsrf()) {
        $message = ['type' => 'error', 'text' => 'CSRF校验失败，请刷新重试'];
    } else {
        try {
            $targetDb = trim((string)($_POST['db'] ?? ''));
            if (!DBManager::validateDbName($targetDb)) {
                throw new RuntimeException('非法数据库名称');
            }
            $db = getDb();
            $db->selectDb($targetDb);
            $_SESSION['db_config']['dbname'] = $targetDb;
            $message = ['type' => 'success', 'text' => '已切换到数据库: ' . $targetDb];
        } catch (Exception $e) {
            error_log('切换库异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => '切换数据库失败'];
        }
    }
    $action = 'tables';
}

/* ---------- 执行 SQL（POST + CSRF + 长度上限 + 白名单/黑名单防护） ---------- */
if ($action === 'execute_sql' && isset($_SESSION['db_config']) && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!checkCsrf()) {
        $message = ['type' => 'error', 'text' => 'CSRF校验失败，请刷新重试'];
    } else {
        try {
            $sql = (string)($_POST['sql'] ?? '');
            if (strlen($sql) > SQL_MAX_LENGTH) {
                throw new RuntimeException('SQL 语句过长（上限 ' . SQL_MAX_LENGTH . ' 字节）');
            }
            $db = getDb();
            $execResult = $db->executeSql($sql);
        } catch (mysqli_sql_exception $e) {
            error_log('执行SQL异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => 'SQL 执行失败，请检查语句'];
        } catch (Exception $e) {
            error_log('执行SQL异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => $e->getMessage()];
        }
    }
}

/* ---------- 删除表（POST + CSRF + 表名校验） ---------- */
if ($action === 'drop_table' && isset($_SESSION['db_config']) && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!checkCsrf()) {
        $message = ['type' => 'error', 'text' => 'CSRF校验失败，请刷新重试'];
    } else {
        try {
            $db = getDb();
            $table = trim((string)($_POST['table'] ?? ''));
            if (!DBManager::validateTableName($table)) {
                throw new RuntimeException('非法表名');
            }
            $db->dropTable($table);
            $message = ['type' => 'success', 'text' => '表 ' . $table . ' 已成功删除'];
        } catch (mysqli_sql_exception $e) {
            error_log('删除表异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => '删除表失败'];
        } catch (Exception $e) {
            error_log('删除表异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => $e->getMessage()];
        }
    }
    $action = 'tables';
}

/* ---------- 行操作：新增 / 编辑 / 删除 ---------- */
if (in_array($action, ['update_row', 'delete_row', 'insert_row'], true) && isset($_SESSION['db_config']) && isset($_GET['table'])) {
    if (!checkCsrf()) {
        $message = ['type' => 'error', 'text' => 'CSRF校验失败，请刷新重试'];
        $action = 'view_table';
    } else {
        try {
            $db = getDb();
            $table = trim((string)$_GET['table']);
            if (!DBManager::validateTableName($table)) {
                throw new RuntimeException('非法表名');
            }
            $primaryKey = $db->getPrimaryKey($table);
            if (!$primaryKey) {
                throw new RuntimeException('表 ' . $table . ' 没有主键，无法执行此操作');
            }

            if ($action === 'update_row' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['id'])) {
                $db->updateTableRow($table, filterRowData($db, $table, $_POST), $primaryKey, $_POST['id']);
                $message = ['type' => 'success', 'text' => '数据已成功更新'];
                $action = 'view_table';
            }

            if ($action === 'delete_row' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['id'])) {
                $db->deleteTableRow($table, $primaryKey, $_POST['id']);
                $message = ['type' => 'success', 'text' => '数据已成功删除'];
                $action = 'view_table';
            }

            if ($action === 'insert_row' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
                $db->insertTableRow($table, filterRowData($db, $table, $_POST));
                $message = ['type' => 'success', 'text' => '数据已成功插入'];
                $action = 'view_table';
            }
        } catch (mysqli_sql_exception $e) {
            error_log('行操作异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => substr((string)$e->getMessage(), 0, 200)];
            $action = 'view_table';
        } catch (Exception $e) {
            error_log('行操作异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => $e->getMessage()];
            $action = 'view_table';
        }
    }
}

/* ---------- 导出单表 SQL ---------- */
if ($action === 'export_sql' && isset($_SESSION['db_config']) && isset($_GET['table'])) {
    try {
        $table = trim((string)$_GET['table']);
        if (!DBManager::validateTableName($table)) {
            throw new RuntimeException('非法表名');
        }
        $db = getDb();
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment;filename="' . $table . '_' . date('YmdHis') . '.sql"');
        $db->exportSql($table);
        exit;
    } catch (Exception $e) {
        error_log('导出SQL异常: ' . substr((string)$e->getMessage(), 0, 500));
        $message = ['type' => 'error', 'text' => '导出SQL失败'];
    }
    $action = 'view_table';
}

/* ---------- 导入 SQL 文件（POST + CSRF + 大小/长度限制） ---------- */
if ($action === 'import_sql' && isset($_SESSION['db_config']) && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!checkCsrf()) {
        $message = ['type' => 'error', 'text' => 'CSRF校验失败，请刷新重试'];
    } else {
        try {
            if (!isset($_FILES['sqlfile']) || (int)($_FILES['sqlfile']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                throw new RuntimeException('请上传 SQL 文件');
            }
            if ((int)$_FILES['sqlfile']['size'] > SQL_MAX_LENGTH) {
                throw new RuntimeException('SQL 文件不能超过 ' . (int)(SQL_MAX_LENGTH / 1048576) . 'MB，大文件请使用命令行 mysql 导入');
            }
            $sqlContent = (string)file_get_contents((string)$_FILES['sqlfile']['tmp_name']);
            $db = getDb();
            $execResult = $db->executeSql($sqlContent);
            $message = ['type' => 'success', 'text' => 'SQL 文件导入执行完成'];
        } catch (mysqli_sql_exception $e) {
            error_log('导入SQL异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => 'SQL 执行失败，请检查语句'];
        } catch (Exception $e) {
            error_log('导入SQL异常: ' . substr((string)$e->getMessage(), 0, 500));
            $message = ['type' => 'error', 'text' => $e->getMessage()];
        }
    }
}

/* ---------- 退出登录（原版缺 CSRF 校验） ---------- */
if ($action === 'logout') {
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && checkCsrf()) {
        $_SESSION = [];
        session_destroy();
        session_start();
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $action = 'login';
        $message = ['type' => 'success', 'text' => '已成功退出登录'];
    } else {
        $message = ['type' => 'error', 'text' => 'CSRF校验失败，请刷新重试'];
        $action = 'tables';
    }
}

/* ---------- 只读页面统一建连 ---------- */
if (in_array($action, ['tables', 'view_table', 'view_structure', 'sql'], true) && isset($_SESSION['db_config'])) {
    try {
        $db = getDb();
    } catch (Exception $e) {
        error_log('连接初始化异常: ' . substr((string)$e->getMessage(), 0, 500));
        $message = ['type' => 'error', 'text' => '数据库连接失败，请重新登录'];
        $_SESSION = [];
        session_destroy();
        session_start();
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $action = 'login';
    }
}
$csrfToken = csrfToken();
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nodeewa-数据库管理工具（安全优化版）</title>
    <style>
        @font-face {font-family: 'Xst';src: url('xst.woff2') format('woff2');}
        * {font-family: 'Xst', 楷体, "STKaiti", "PingFang SC", "Droid Sans Fallback", serif;}
    </style>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#3b82f6', secondary: '#64748b', success: '#10b981',
                        danger: '#ef4444', neutral: '#f1f5f9',
                    },
                    fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
                }
            }
        }
    </script>
    <style type="text/tailwindcss">
        @layer utilities {
            .content-auto { content-visibility: auto; }
            .table-wrapper { max-height: 70vh; overflow-y: auto; }
            .sticky-header th { position: sticky; top: 0; z-index: 10; }
            .btn { @apply px-3 py-1.5 rounded font-medium transition-all duration-200 text-sm; }
            .btn-primary { @apply bg-primary text-white hover:bg-primary/90; }
            .btn-secondary { @apply bg-secondary text-white hover:bg-secondary/90; }
            .btn-danger { @apply bg-danger text-white hover:bg-danger/90; }
            .btn-outline { @apply border border-gray-300 text-gray-700 hover:bg-gray-50; }
            .card { @apply bg-white rounded-lg shadow-md overflow-hidden; }
            .form-input { @apply w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary/50; }
            .sql-snippet { @apply px-3 py-1.5 bg-gray-100 rounded text-sm cursor-pointer hover:bg-gray-200 transition-colors; }
            .sql-history-item { @apply px-2 py-1 bg-gray-50 rounded text-xs mb-1 cursor-pointer hover:bg-gray-200 break-all; }
            @media (max-width: 640px) {
                .responsive-table { display: block; width: 100%; }
                .responsive-table thead { display: none; }
                .responsive-table tbody { display: block; width: 100%; }
                .responsive-table tr { display: block; margin-bottom: 1rem; border: 1px solid #ddd; border-radius: 4px; }
                .responsive-table td { display: flex; justify-content: space-between; padding: 0.75rem; text-align: right; border-bottom: 1px solid #eee; }
                .responsive-table td::before { content: attr(data-label); font-weight: bold; text-align: left; flex: 1; margin-right: 1rem; }
                .table-actions { justify-content: flex-end !important; }
                .table-actions::before { content: "操作:" !important; }
            }
        }
    </style>
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto px-2 sm:px-4 py-6 max-w-7xl md:max-w-8xl lg:max-w-9xl">
        <?php if (!empty($message['text'])): ?>
            <div class="mb-4 p-4 rounded-md
                <?= $message['type'] == 'error' ? 'bg-red-100 text-red-700 border border-red-200' :
                   'bg-green-100 text-green-700 border border-green-200' ?>">
                <?= h($message['text']) ?>
            </div>
        <?php endif; ?>

        <?php if ($action == 'login'): ?>
            <div class="max-w-md mx-auto">
                <div class="card p-6">
                    <h2 class="text-2xl font-bold mb-6 text-center text-gray-700">数据库登录</h2>
                    <form method="post" action="?action=login" autocomplete="on">
                        <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                        <div class="mb-4">
                            <label class="block text-gray-700 mb-2" for="host">主机</label>
                            <input type="text" id="host" name="host" value="localhost" required class="form-input">
                        </div>
                        <div class="mb-4">
                            <label class="block text-gray-700 mb-2" for="user">用户名</label>
                            <input type="text" id="user" name="user" value="root" required class="form-input">
                        </div>
                        <div class="mb-4">
                            <label class="block text-gray-700 mb-2" for="pass">密码</label>
                            <input type="password" id="pass" name="pass" autocomplete="current-password" class="form-input">
                        </div>
                        <div class="mb-6">
                            <label class="block text-gray-700 mb-2" for="dbname">数据库</label>
                            <input type="text" id="dbname" name="dbname" placeholder="可选" class="form-input">
                        </div>
                        <div>
                            <button type="submit" class="btn btn-primary w-full">
                                <i class="fa fa-sign-in mr-2"></i>登录
                            </button>
                        </div>
                    </form>
                    <p class="text-xs text-gray-400 mt-4">提示：仅建议在可信内网使用；建议为工具配置最小权限数据库账号。</p>
                </div>
            </div>
        <?php else: ?>
            <div class="card mb-6">
                <div class="bg-gray-50 px-4 sm:px-6 py-4 border-b border-gray-200 flex flex-wrap items-center justify-between gap-4">
                    <div class="flex flex-wrap space-x-2 sm:space-x-4">
                        <a href="?action=tables" class="text-primary hover:text-primary/80 flex items-center py-1">
                            <i class="fa fa-table mr-1"></i> 表列表
                        </a>
                        <button id="sqlBtn" class="text-primary hover:text-primary/80 flex items-center py-1">
                            <i class="fa fa-code mr-1"></i> 执行SQL
                        </button>
                        <form method="post" action="?action=logout" class="inline">
                            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                            <button type="submit" class="text-danger hover:text-danger/80 flex items-center py-1">
                                <i class="fa fa-sign-out mr-1"></i> 退出登录
                            </button>
                        </form>
                    </div>
                    <div class="text-gray-600 text-sm sm:text-base">
                        当前数据库: <span class="font-medium"><?= h($_SESSION['db_config']['dbname'] ?? '未选择') ?></span>
                    </div>
                </div>
            </div>

            <?php if ($action == 'tables'): ?>
                <div class="card mb-6">
                    <div class="p-4 sm:p-6">
                        <h2 class="text-xl font-bold mb-4 text-gray-700">数据库列表</h2>
                        <div class="overflow-x-auto">
                            <table class="min-w-full bg-white border border-gray-200 responsive-table">
                                <thead class="bg-gray-50">
                                    <tr><th class="py-3 px-4 border-b text-left">数据库名</th></tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($db->getDatabases() as $d):
                                        $dbName = (string)$d['Database'];
                                        $isCurrent = ($_SESSION['db_config']['dbname'] ?? '') == $dbName;
                                    ?>
                                        <tr class="hover:bg-gray-50 <?= $isCurrent ? 'bg-blue-50' : '' ?>">
                                            <td class="py-3 px-4 border-b" data-label="数据库名">
                                                <div class="flex flex-wrap items-center gap-2">
                                                    <?= h($dbName) ?>
                                                    <?php if (!$isCurrent): ?>
                                                        <form method="post" action="?action=change_db" class="inline">
                                                            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                                            <input type="hidden" name="db" value="<?= h($dbName) ?>">
                                                            <button type="submit" class="btn btn-primary btn-sm">切换</button>
                                                        </form>
                                                    <?php else: ?>
                                                        <span class="text-xs bg-primary/20 text-primary px-2 py-0.5 rounded">当前</span>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <?php if (!empty($_SESSION['db_config']['dbname'])): ?>
                    <div class="card mb-6">
                        <div class="p-4 sm:p-6">
                            <h2 class="text-xl font-bold mb-4 text-gray-700">导入SQL文件</h2>
                            <form method="post" action="?action=import_sql" enctype="multipart/form-data">
                                <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                <div class="flex flex-wrap gap-3 items-center">
                                    <input type="file" name="sqlfile" accept=".sql" class="form-input w-auto">
                                    <button type="submit" class="btn btn-primary"><i class="fa fa-upload mr-1"></i>导入执行</button>
                                </div>
                                <p class="text-xs text-gray-400 mt-2">仅可导入不含 DDL（create/alter/drop）的语句，文件不超过 <?= (int)(SQL_MAX_LENGTH / 1048576) ?>MB；大文件建表请用命令行 mysql 导入。</p>
                            </form>
                        </div>
                    </div>
                    <div class="card">
                        <div class="p-4 sm:p-6">
                            <h2 class="text-xl font-bold mb-4 text-gray-700">表列表</h2>
                            <div class="overflow-x-auto">
                                <table class="min-w-full bg-white border border-gray-200 responsive-table">
                                    <thead class="bg-gray-50">
                                        <tr>
                                            <th class="py-3 px-4 border-b text-left">表名</th>
                                            <th class="py-3 px-4 border-b text-left">操作</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($db->getTables() as $t):
                                            $tableName = (string)$t['TableName'];
                                        ?>
                                            <tr class="hover:bg-gray-50">
                                                <td class="py-3 px-4 border-b" data-label="表名"><?= h($tableName) ?></td>
                                                <td class="py-3 px-4 border-b table-actions">
                                                    <div class="flex flex-wrap gap-2">
                                                        <a href="?action=view_table&table=<?= urlencode($tableName) ?>" class="btn btn-primary">查看数据</a>
                                                        <a href="?action=view_structure&table=<?= urlencode($tableName) ?>" class="btn btn-secondary">表结构</a>
                                                        <form method="post" action="?action=drop_table" class="inline" onsubmit="return confirm(<?= jsq('确定删除表 ' . $tableName . '？不可恢复！') ?>)">
                                                            <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                                            <input type="hidden" name="table" value="<?= h($tableName) ?>">
                                                            <button type="submit" class="btn btn-danger">删除表</button>
                                                        </form>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($action == 'view_structure' && isset($_GET['table'])):
                $table = trim((string)$_GET['table']);
                try {
                    $structure = $db->getTableStructure($table);
                } catch (Exception $e) {
                    error_log("查看表结构异常: " . substr((string)$e->getMessage(), 0, 500));
                    $message = ['type' => 'error', 'text' => "读取表结构失败"];
                    $structure = [];
                    $action = 'tables';
                }
            ?>
                <?php if ($action != 'tables'): ?>
                <div class="card">
                    <div class="p-4 sm:p-6">
                        <div class="flex flex-wrap justify-between items-center gap-4 mb-4">
                            <h2 class="text-xl font-bold text-gray-700">表结构: <?= h($table) ?></h2>
                            <div class="flex flex-wrap gap-2">
                                <a href="?action=tables" class="btn btn-outline"><i class="fa fa-arrow-left mr-1"></i>返回列表</a>
                                <a href="?action=view_table&table=<?= urlencode($table) ?>" class="btn btn-primary"><i class="fa fa-table mr-1"></i>查看数据</a>
                            </div>
                        </div>

                        <div class="mb-6">
                            <h3 class="text-lg font-semibold mb-3 text-gray-700">字段信息</h3>
                            <div class="overflow-x-auto">
                                <table class="min-w-full bg-white border border-gray-200 responsive-table">
                                    <thead class="bg-gray-50">
                                        <tr>
                                            <th class="py-3 px-4 border-b text-left">字段</th>
                                            <th class="py-3 px-4 border-b text-left">类型</th>
                                            <th class="py-3 px-4 border-b text-left">空</th>
                                            <th class="py-3 px-4 border-b text-left">键</th>
                                            <th class="py-3 px-4 border-b text-left">默认</th>
                                            <th class="py-3 px-4 border-b text-left">额外</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($structure as $field): ?>
                                            <tr class="hover:bg-gray-50">
                                                <td class="py-3 px-4 border-b" data-label="字段"><?= h($field['Field']) ?></td>
                                                <td class="py-3 px-4 border-b" data-label="类型"><?= h($field['Type']) ?></td>
                                                <td class="py-3 px-4 border-b" data-label="空"><?= h($field['Null']) ?></td>
                                                <td class="py-3 px-4 border-b" data-label="键"><?= h($field['Key']) ?></td>
                                                <td class="py-3 px-4 border-b" data-label="默认"><?= h($field['Default'] ?? '') ?></td>
                                                <td class="py-3 px-4 border-b" data-label="额外"><?= h($field['Extra']) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <div>
                            <h3 class="text-lg font-semibold mb-3 text-gray-700">执行SQL查询（DDL/高危语句已拦截）</h3>
                            <form method="post" action="?action=execute_sql" id="sqlFormStructure">
                                <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                <div class="mb-4">
                                    <textarea name="sql" rows="3" class="form-input font-mono text-sm" id="sqlTextarea"
                                        placeholder="例如: SELECT * FROM <?= h($table) ?> LIMIT 10"></textarea>
                                </div>
                                <div class="mb-3">
                                    <div class="text-sm text-gray-600 mb-1">SQL历史记录（浏览器本地缓存）</div>
                                    <div id="sqlHistoryBox" class="max-h-32 overflow-y-auto border rounded p-2 bg-gray-50"></div>
                                    <button type="button" id="clearHistoryBtn" class="btn btn-outline mt-2 text-xs">清空历史</button>
                                </div>
                                <div>
                                    <button type="submit" class="btn btn-primary"><i class="fa fa-play mr-1"></i>执行</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($action == 'view_table' && isset($_GET['table'])):
                $table = trim((string)$_GET['table']);
                try {
                    $primaryKey = $db->getPrimaryKey($table);
                    $structure = $db->getTableStructure($table);
                    $editRow = null;
                    if (isset($_GET['edit']) && $primaryKey) {
                        $editRow = $db->getTableRow($table, (string)$_GET['edit'], $primaryKey);
                    }
                    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
                    $limit = 20;
                    $total = $db->getTableDataCount($table);
                    $totalPages = max(1, (int)ceil($total / $limit));
                    $page = min($page, $totalPages);
                    $data = $db->getTableData($table, $page, $limit);
                } catch (Exception $e) {
                    error_log("查看表数据异常: " . substr((string)$e->getMessage(), 0, 500));
                    $message = ['type' => 'error', 'text' => "读取表数据失败"];
                    $action = 'tables';
                    $data = [];
                }
            ?>
                <?php if ($action != 'tables'): ?>
                <div class="card">
                    <div class="p-4 sm:p-6">
                        <div class="flex flex-wrap justify-between items-center gap-4 mb-6">
                            <h2 class="text-xl font-bold text-gray-700">表数据: <?= h($table) ?></h2>
                            <div class="flex flex-wrap gap-2">
                                <a href="?action=tables" class="btn btn-outline"><i class="fa fa-arrow-left mr-1"></i>返回列表</a>
                                <a href="?action=view_structure&table=<?= urlencode($table) ?>" class="btn btn-secondary"><i class="fa fa-cogs mr-1"></i>表结构</a>
                                <a href="?action=export_sql&table=<?= urlencode($table) ?>" class="btn btn-secondary"><i class="fa fa-download mr-1"></i>导出SQL</a>
                                <button type="button" onclick="document.getElementById('insertForm').classList.toggle('hidden')" class="btn btn-primary"><i class="fa fa-plus mr-1"></i>添加数据</button>
                            </div>
                        </div>

                        <div id="insertForm" class="mb-6 p-4 bg-gray-50 rounded-lg hidden">
                            <h3 class="text-lg font-semibold mb-3 text-gray-700">添加新记录</h3>
                            <form method="post" action="?action=insert_row&table=<?= urlencode($table) ?>">
                                <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                    <?php foreach ($structure as $field):
                                        if (strpos((string)$field['Extra'], 'auto_increment') !== false) continue;
                                    ?>
                                        <div>
                                            <label class="block text-gray-700 mb-1 text-sm" for="insert_<?= h($field['Field']) ?>">
                                                <?= h($field['Field']) ?>
                                                <span class="text-gray-500">(<?= h($field['Type']) ?>)</span>
                                                <?php if ($field['Null'] != 'YES'): ?><span class="text-danger">*</span><?php endif; ?>
                                            </label>
                                            <input type="text" id="insert_<?= h($field['Field']) ?>" name="<?= h($field['Field']) ?>" class="form-input" <?= $field['Null'] != 'YES' ? 'required' : '' ?>>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                                <div class="mt-4">
                                    <button type="submit" class="btn btn-primary"><i class="fa fa-save mr-1"></i>保存</button>
                                    <button type="button" onclick="document.getElementById('insertForm').classList.add('hidden')" class="btn btn-outline ml-2">取消</button>
                                </div>
                            </form>
                        </div>

                        <?php if ($editRow): ?>
                            <div class="mb-6 p-4 bg-gray-50 rounded-lg">
                                <h3 class="text-lg font-semibold mb-3 text-gray-700">编辑记录</h3>
                                <form method="post" action="?action=update_row&table=<?= urlencode($table) ?>">
                                    <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                    <input type="hidden" name="id" value="<?= h($editRow[$primaryKey]) ?>">
                                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                        <?php foreach ($structure as $field):
                                            $fieldName = (string)$field['Field'];
                                        ?>
                                            <div>
                                                <label class="block text-gray-700 mb-1 text-sm" for="edit_<?= h($fieldName) ?>">
                                                    <?= h($fieldName) ?>
                                                    <span class="text-gray-500">(<?= h($field['Type']) ?>)</span>
                                                    <?php if ($field['Null'] != 'YES'): ?><span class="text-danger">*</span><?php endif; ?>
                                                    <?php if ($fieldName == $primaryKey): ?><span class="text-gray-500 text-xs">(主键不可修改)</span><?php endif; ?>
                                                </label>
                                                <input type="text" id="edit_<?= h($fieldName) ?>" name="<?= h($fieldName) ?>"
                                                    value="<?= h($editRow[$fieldName] ?? '') ?>" class="form-input"
                                                    <?= $field['Null'] != 'YES' ? 'required' : '' ?>
                                                    <?= $fieldName == $primaryKey ? 'readonly' : '' ?>>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                    <div class="mt-4">
                                        <button type="submit" class="btn btn-primary"><i class="fa fa-save mr-1"></i>保存</button>
                                        <a href="?action=view_table&table=<?= urlencode($table) ?>&page=<?= $page ?>" class="btn btn-outline ml-2">取消</a>
                                    </div>
                                </form>
                            </div>
                        <?php endif; ?>

                        <div class="table-wrapper">
                            <table class="min-w-full bg-white border border-gray-200 sticky-header responsive-table">
                                <?php if (!empty($data)): ?>
                                    <thead class="bg-gray-50">
                                        <tr>
                                            <?php foreach (array_keys($data[0]) as $col): ?>
                                                <th class="py-3 px-4 border-b text-left bg-gray-50">
                                                    <?= h($col) ?>
                                                    <?php if ($primaryKey && $col == $primaryKey): ?>
                                                        <span class="ml-1 text-xs bg-blue-100 text-blue-800 px-1 rounded">主键</span>
                                                    <?php endif; ?>
                                                </th>
                                            <?php endforeach; ?>
                                            <th class="py-3 px-4 border-b text-left bg-gray-50">操作</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($data as $row): ?>
                                            <tr class="hover:bg-gray-50">
                                                <?php foreach ($row as $key => $val):
                                                    $isBin = false;
                                                    foreach ($structure as $fd) {
                                                        if ((string)$fd['Field'] === $key && (stripos((string)$fd['Type'], 'blob') !== false || stripos((string)$fd['Type'], 'binary') !== false)) {
                                                            $isBin = true;
                                                            break;
                                                        }
                                                    }
                                                ?>
                                                    <td class="py-3 px-4 border-b" data-label="<?= h($key) ?>">
                                                        <?php if ($isBin): ?>[BINARY DATA]<?php else: ?><?= h($val ?? '') ?><?php endif; ?>
                                                    </td>
                                                <?php endforeach; ?>
                                                <td class="py-3 px-4 border-b table-actions">
                                                    <div class="flex flex-wrap gap-1">
                                                        <?php if ($primaryKey): ?>
                                                            <a href="?action=view_table&table=<?= urlencode($table) ?>&page=<?= $page ?>&edit=<?= urlencode((string)$row[$primaryKey]) ?>" class="btn btn-primary btn-sm"><i class="fa fa-edit"></i></a>
                                                            <form method="post" action="?action=delete_row&table=<?= urlencode($table) ?>&page=<?= $page ?>" class="inline" onsubmit="return confirm('确定删除这条记录？')">
                                                                <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                                                                <input type="hidden" name="id" value="<?= h($row[$primaryKey]) ?>">
                                                                <button type="submit" class="btn btn-danger btn-sm"><i class="fa fa-trash"></i></button>
                                                            </form>
                                                        <?php else: ?>
                                                            <span class="text-gray-500 text-sm">无主键，无法编辑</span>
                                                        <?php endif; ?>
                                                    </div>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                <?php else: ?>
                                    <tr>
                                        <td colspan="<?= count($structure) + 1 ?>" class="py-4 px-4 text-center text-gray-500">没有数据</td>
                                    </tr>
                                <?php endif; ?>
                            </table>
                        </div>

                        <?php if ($totalPages > 1): ?>
                            <div class="mt-4 flex flex-wrap justify-center">
                                <div class="inline-flex rounded-md shadow">
                                    <?php if ($page > 1): ?>
                                        <a href="?action=view_table&table=<?= urlencode($table) ?>&page=<?= $page - 1 ?>" class="px-3 py-2 bg-white border border-gray-300 text-sm font-medium text-gray-500 hover:bg-gray-50 rounded-l-md"><i class="fa fa-chevron-left"></i></a>
                                    <?php endif; ?>
                                    <?php
                                    $startPage = max(1, $page - 2);
                                    $endPage = min($totalPages, $page + 2);
                                    if (isset($_SERVER['HTTP_USER_AGENT']) && preg_match('/Mobile/', $_SERVER['HTTP_USER_AGENT'])) {
                                        $startPage = max(1, $page - 1);
                                        $endPage = min($totalPages, $page + 1);
                                    }
                                    for ($i = $startPage; $i <= $endPage; $i++):
                                    ?>
                                        <?php if ($i == $page): ?>
                                            <a href="?action=view_table&table=<?= urlencode($table) ?>&page=<?= $i ?>" class="px-3 py-2 bg-primary border border-primary text-sm font-medium text-white"><?= $i ?></a>
                                        <?php else: ?>
                                            <a href="?action=view_table&table=<?= urlencode($table) ?>&page=<?= $i ?>" class="px-3 py-2 bg-white border border-gray-300 text-sm font-medium text-gray-500 hover:bg-gray-50"><?= $i ?></a>
                                        <?php endif; ?>
                                    <?php endfor; ?>
                                    <?php if ($page < $totalPages): ?>
                                        <a href="?action=view_table&table=<?= urlencode($table) ?>&page=<?= $page + 1 ?>" class="px-3 py-2 bg-white border border-gray-300 text-sm font-medium text-gray-500 hover:bg-gray-50 rounded-r-md"><i class="fa fa-chevron-right"></i></a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endif; ?>
            <?php endif; ?>

            <?php if ($db instanceof DBManager) { $db->close(); } ?>
        <?php endif; ?>
    </div>

    <!-- SQL执行弹窗 -->
    <div id="sqlModal" class="fixed inset-0 bg-black/50 hidden items-center justify-center z-50 p-4">
        <div class="card w-full max-w-4xl max-h-[85vh] flex flex-col">
            <div class="bg-gray-50 px-4 sm:px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-gray-700">执行SQL语句</h3>
                <button type="button" id="closeModal" class="text-gray-500 hover:text-gray-700"><i class="fa fa-times"></i></button>
            </div>
            <div class="p-4 sm:p-6 overflow-y-auto flex-grow">
                <form id="sqlForm" method="post" action="?action=execute_sql">
                    <input type="hidden" name="csrf" value="<?= h($csrfToken) ?>">
                    <div class="mb-4">
                        <textarea name="sql" id="sqlInput" rows="8" class="form-input font-mono text-sm"
                            placeholder="输入SQL语句，可执行多条，用分号分隔"><?= h($_POST['sql'] ?? '') ?></textarea>
                    </div>
                    <div class="mb-4">
                        <div class="text-sm text-gray-600 mb-1">SQL历史记录（浏览器本地缓存）</div>
                        <div id="sqlModalHistoryBox" class="max-h-32 overflow-y-auto border rounded p-2 bg-gray-50"></div>
                        <button type="button" id="clearModalHistoryBtn" class="btn btn-outline mt-2 text-xs">清空历史</button>
                    </div>
                    <div class="flex justify-end">
                        <button type="submit" class="btn btn-primary"><i class="fa fa-play mr-1"></i>执行</button>
                    </div>
                </form>

                <div class="mt-6">
                    <h4 class="text-md font-bold text-gray-700 mb-3">常用SQL语句</h4>
                    <div class="flex flex-wrap gap-2">
                        <div class="sql-snippet" data-sql="SELECT * FROM " onclick="insertSql(this)">SELECT * FROM</div>
                        <div class="sql-snippet" data-sql="INSERT INTO () VALUES ()" onclick="insertSql(this)">INSERT</div>
                        <div class="sql-snippet" data-sql="UPDATE SET WHERE " onclick="insertSql(this)">UPDATE</div>
                        <div class="sql-snippet" data-sql="DELETE FROM WHERE " onclick="insertSql(this)">DELETE</div>
                        <div class="sql-snippet" data-sql="SHOW TABLES" onclick="insertSql(this)">SHOW TABLES</div>
                        <div class="sql-snippet" data-sql="DESCRIBE " onclick="insertSql(this)">DESCRIBE 表</div>
                        <div class="sql-snippet" data-sql="SELECT COUNT(*) FROM " onclick="insertSql(this)">COUNT</div>
                        <div class="sql-snippet" data-sql="SET NAMES utf8mb4" onclick="insertSql(this)">SET NAMES</div>
                    </div>
                </div>

                <?php if (!empty($execResult)): ?>
                    <div class="mt-6">
                        <h4 class="text-md font-bold text-gray-700 mb-3">执行结果</h4>
                        <div class="space-y-4">
                            <?php foreach ($execResult as $item): ?>
                                <?php if ($item['type'] == 'error'): ?>
                                    <div class="p-3 bg-red-50 border border-red-200 rounded-md text-red-700"><?= h($item['message']) ?></div>
                                <?php elseif ($item['type'] == 'info'): ?>
                                    <div class="p-3 bg-blue-50 border border-blue-200 rounded-md text-blue-700"><?= h($item['message']) ?></div>
                                <?php else: ?>
                                    <div class="overflow-x-auto">
                                        <?php if (!empty($item['truncated'])): ?>
                                            <div class="mb-2 text-xs text-amber-600">结果过多，仅显示前 <?= SQL_RESULT_MAX_ROWS ?> 行（共 <?= (int)($item['total'] ?? 0) ?> 行）</div>
                                        <?php endif; ?>
                                        <table class="min-w-full bg-white border border-gray-200 responsive-table">
                                            <thead class="bg-gray-50">
                                                <tr>
                                                    <?php foreach ($item['fields'] as $field): ?>
                                                        <th class="py-2 px-3 border-b text-left text-sm"><?= h($field) ?></th>
                                                    <?php endforeach; ?>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($item['data'] as $row): ?>
                                                    <tr class="hover:bg-gray-50">
                                                        <?php foreach ($row as $key => $val): ?>
                                                            <td class="py-2 px-3 border-b text-sm" data-label="<?= h($key) ?>"><?= h($val ?? '') ?></td>
                                                        <?php endforeach; ?>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        // ===== SQL 历史记录（localStorage 浏览器缓存）=====
        var HISTORY_KEY = 'nodeewa_sql_history';
        var MAX_HISTORY = 20;

        function getHistory() {
            try {
                var arr = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
                return Array.isArray(arr) ? arr : [];
            } catch (e) { return []; }
        }
        function saveToHistory(sql) {
            if (!sql || !sql.trim()) return;
            var arr = getHistory();
            arr = arr.filter(function(s){ return s !== sql; });
            arr.unshift(sql);
            if (arr.length > MAX_HISTORY) arr = arr.slice(0, MAX_HISTORY);
            localStorage.setItem(HISTORY_KEY, JSON.stringify(arr));
        }
        function renderHistory(textarea, box) {
            if (!box) return;
            var arr = getHistory();
            box.innerHTML = '';
            if (arr.length === 0) {
                box.innerHTML = '<div class="text-gray-400 text-xs px-1">暂无历史</div>';
                return;
            }
            arr.forEach(function(sql){
                var el = document.createElement('div');
                el.className = 'sql-history-item';
                el.textContent = sql.length > 80 ? sql.substring(0, 80) + '...' : sql;
                el.title = sql;
                el.addEventListener('click', function(){
                    textarea.value = sql;
                    textarea.focus();
                });
                box.appendChild(el);
            });
        }
        function initHistory(textareaId, boxId, clearBtnId) {
            var textarea = document.getElementById(textareaId);
            var box = document.getElementById(boxId);
            var clearBtn = document.getElementById(clearBtnId);
            if (!textarea || !box) return;
            renderHistory(textarea, box);
            if (clearBtn) {
                clearBtn.addEventListener('click', function(){
                    if (confirm('确定清空SQL历史？')) {
                        localStorage.removeItem(HISTORY_KEY);
                        renderHistory(textarea, box);
                    }
                });
            }
            var form = textarea.closest('form');
            if (form) {
                form.addEventListener('submit', function(){
                    saveToHistory(textarea.value);
                });
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            // 弹窗控制
            var modal = document.getElementById('sqlModal');
            var sqlBtn = document.getElementById('sqlBtn');
            var closeModal = document.getElementById('closeModal');
            var sqlInput = document.getElementById('sqlInput');
            if (sqlBtn && modal) {
                sqlBtn.addEventListener('click', function() {
                    modal.classList.remove('hidden');
                    modal.classList.add('flex');
                    if (sqlInput) sqlInput.focus();
                });
                closeModal.addEventListener('click', function() {
                    modal.classList.add('hidden');
                    modal.classList.remove('flex');
                });
                modal.addEventListener('click', function(e) {
                    if (e.target === modal) {
                        modal.classList.add('hidden');
                        modal.classList.remove('flex');
                    }
                });
                document.addEventListener('keydown', function(e) {
                    if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
                        modal.classList.add('hidden');
                        modal.classList.remove('flex');
                    }
                });
            }

            // SQL历史
            initHistory('sqlInput', 'sqlModalHistoryBox', 'clearModalHistoryBtn');
            initHistory('sqlTextarea', 'sqlHistoryBox', 'clearHistoryBtn');

            // 执行结果时自动打开弹窗
            <?php if (!empty($execResult)): ?>
                if (modal) {
                    modal.classList.remove('hidden');
                    modal.classList.add('flex');
                }
            <?php endif; ?>
        });

        function insertSql(element) {
            var sql = element.getAttribute('data-sql');
            var input = document.getElementById('sqlInput');
            if (!input) return;
            var start = input.selectionStart;
            var end = input.selectionEnd;
            input.value = input.value.substring(0, start) + sql + input.value.substring(end);
            var newCursorPos = start + sql.length;
            input.focus();
            input.setSelectionRange(newCursorPos, newCursorPos);
        }

        function adjustTableLayout() {
            var tables = document.querySelectorAll('.responsive-table');
            tables.forEach(function(table) {
                if (window.innerWidth <= 640) table.classList.add('mobile-layout');
                else table.classList.remove('mobile-layout');
            });
        }
        window.addEventListener('resize', adjustTableLayout);
        adjustTableLayout();
    </script>
</body>
</html>

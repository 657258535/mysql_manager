<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 数据库连接类
class DBManager {
    private $conn;
    private $host;
    private $user;
    private $pass;
    private $dbname;

    public function __construct($host, $user, $pass, $dbname = '') {
        $this->host = $host;
        $this->user = $user;
        $this->pass = $pass;
        $this->dbname = $dbname;
    }

    public function connect() {
        // 先连无库，再手动 select_db，避免 dbname 为空时报错
        $this->conn = new mysqli($this->host, $this->user, $this->pass);
        if ($this->conn->connect_error) {
            throw new Exception("连接失败: " . $this->conn->connect_error);
        }
        $this->conn->set_charset("utf8mb4");
        if (!empty($this->dbname)) {
            $this->selectDb($this->dbname);
        }
        return $this;
    }

    // 真正切换连接选中的库
    public function selectDb(string $dbName): bool {
        if (!$this->conn->select_db($dbName)) {
            throw new Exception("切换数据库失败: " . $this->conn->error);
        }
        $this->dbname = $dbName;
        return true;
    }

    // 暴露连接，供类外读取 error 等
    public function getConn() {
        return $this->conn;
    }

    public function getCurrentDatabase() {
        $res = $this->conn->query("SELECT DATABASE() as now_db");
        if (!$res) throw new Exception("查询当前库失败：" . $this->conn->error);
        $row = $res->fetch_assoc();
        return $row['now_db'];
    }

    // 表名/库名校验：仅字母数字下划线
    public static function validateTableName(string $name): bool {
        return preg_match('/^[a-zA-Z0-9_]+$/', $name) === 1;
    }
    public static function validateDbName(string $name): bool {
        return preg_match('/^[a-zA-Z0-9_]+$/', $name) === 1;
    }

    public function getDatabases() {
        $result = $this->conn->query("SHOW DATABASES");
        if (!$result) throw new Exception("查询数据库列表失败：" . $this->conn->error);
        return $result->fetch_all(MYSQLI_ASSOC);
    }

    public function getTables() {
        $result = $this->conn->query("SHOW TABLES");
        if (!$result) throw new Exception("查询表列表失败：" . $this->conn->error);
        $raw = $result->fetch_all(MYSQLI_NUM);
        $out = [];
        foreach ($raw as $row) {
            $out[] = ['TableName' => $row[0]];
        }
        return $out;
    }

    public function getTableStructure($table) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        $result = $this->conn->query("DESCRIBE `$table`");
        if (!$result) throw new Exception("获取表结构失败：" . $this->conn->error);
        return $result->fetch_all(MYSQLI_ASSOC);
    }

    public function alterTable($sql) {
        return $this->conn->query($sql);
    }

    public function dropTable($table) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        return $this->conn->query("DROP TABLE `$table`");
    }

    public function getTableDataCount($table) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        $result = $this->conn->query("SELECT COUNT(*) as total FROM `$table`");
        if (!$result) throw new Exception("统计表行数失败：" . $this->conn->error);
        $row = $result->fetch_assoc();
        return (int)$row['total'];
    }

    public function getTableData($table, $page = 1, $limit = 20) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        $page = max(1, (int)$page);
        $limit = max(1, (int)$limit);
        $offset = ($page - 1) * $limit;
        $result = $this->conn->query("SELECT * FROM `$table` LIMIT $offset, $limit");
        if (!$result) throw new Exception("读取表数据失败：" . $this->conn->error);
        return $result->fetch_all(MYSQLI_ASSOC);
    }

    public function getTableRow($table, $id, $primaryKey) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        $pk = $this->conn->real_escape_string($primaryKey);
        $val = $this->conn->real_escape_string($id);
        $result = $this->conn->query("SELECT * FROM `$table` WHERE `$pk` = '$val' LIMIT 1");
        if (!$result) throw new Exception("读取单行失败：" . $this->conn->error);
        return $result->fetch_assoc();
    }

    public function updateTableRow($table, $data, $primaryKey, $id) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        $setClause = [];
        foreach ($data as $key => $value) {
            if ($key != $primaryKey && self::validateTableName($key)) {
                $setClause[] = "`$key` = '" . $this->conn->real_escape_string($value) . "'";
            }
        }
        if (empty($setClause)) return false;
        $pkEsc = $this->conn->real_escape_string($primaryKey);
        $idEsc = $this->conn->real_escape_string($id);
        $sql = "UPDATE `$table` SET " . implode(', ', $setClause) . " WHERE `$pkEsc` = '$idEsc'";
        return $this->conn->query($sql);
    }

    public function deleteTableRow($table, $primaryKey, $id) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        $pkEsc = $this->conn->real_escape_string($primaryKey);
        $idEsc = $this->conn->real_escape_string($id);
        return $this->conn->query("DELETE FROM `$table` WHERE `$pkEsc` = '$idEsc'");
    }

    public function insertTableRow($table, $data) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        $columns = [];
        $values = [];
        foreach ($data as $key => $value) {
            if (self::validateTableName($key)) {
                $columns[] = "`$key`";
                $values[] = "'" . $this->conn->real_escape_string($value) . "'";
            }
        }
        if (empty($columns)) return false;
        $sql = "INSERT INTO `$table` (" . implode(', ', $columns) . ") VALUES (" . implode(', ', $values) . ")";
        return $this->conn->query($sql);
    }

    public function getPrimaryKey($table) {
        if (!self::validateTableName($table)) throw new Exception("非法表名");
        $result = $this->conn->query("DESCRIBE `$table`");
        if (!$result) throw new Exception("获取主键失败：" . $this->conn->error);
        while ($row = $result->fetch_assoc()) {
            if ($row['Key'] == 'PRI') {
                return $row['Field'];
            }
        }
        return null;
    }

    // 修复 multi_query：同步消费所有结果，防止 Commands out of sync
    public function executeSql($sql) {
        $output = [];
        $res = $this->conn->multi_query($sql);
        if ($res === FALSE) {
            $output[] = ['type' => 'error', 'message' => "错误: " . $this->conn->error];
            // 清空残留结果，恢复连接状态
            while ($this->conn->more_results()) {
                $this->conn->next_result();
            }
            return $output;
        }

        do {
            if ($resSet = $this->conn->store_result()) {
                $output[] = [
                    'type' => 'result',
                    'data' => $resSet->fetch_all(MYSQLI_ASSOC),
                    'fields' => $this->getFieldNames($resSet)
                ];
                $resSet->free();
            } else {
                if (strlen($this->conn->error) > 0) {
                    $output[] = ['type' => 'error', 'message' => 'SQL执行错误：' . $this->conn->error];
                } else {
                    $output[] = ['type' => 'info', 'message' => "受影响行数: " . $this->conn->affected_rows];
                }
            }
        } while ($this->conn->more_results() && $this->conn->next_result());
        return $output;
    }

    private function getFieldNames($result) {
        $fields = [];
        while ($field = $result->fetch_field()) {
            $fields[] = $field->name;
        }
        return $fields;
    }

    public function close() {
        if (isset($this->conn) && $this->conn instanceof mysqli) {
            try {
                $this->conn->close();
            } catch (Exception $e) {
            }
            $this->conn = null;
        }
    }
}

// 处理用户操作
$action = $_REQUEST['action'] ?? 'login';
$message = ['type' => '', 'text' => ''];
$db = null;

if ($action == 'login' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        $db = (new DBManager($_POST['host'], $_POST['user'], $_POST['pass']))->connect();
        $_SESSION['db_config'] = [
            'host' => $_POST['host'],
            'user' => $_POST['user'],
            'pass' => $_POST['pass'],
            'dbname' => $_POST['dbname'] ?? ''
        ];
        if (!empty($_SESSION['db_config']['dbname'])) {
            $db->selectDb($_SESSION['db_config']['dbname']);
        }
        $action = 'tables';
    } catch (Exception $e) {
        $message = ['type' => 'error', 'text' => $e->getMessage()];
    }
}

// 【修复串库】先更新 session，再重建连接，切换立即生效
if ($action == 'change_db' && isset($_SESSION['db_config'])) {
    try {
        $targetDb = $_GET['db'];
        if (!DBManager::validateDbName($targetDb)) {
            throw new Exception("非法数据库名称");
        }
        $_SESSION['db_config']['dbname'] = $targetDb;
        $db = (new DBManager(...array_values($_SESSION['db_config'])))->connect();
        $db->selectDb($targetDb);
        $message = ['type' => 'success', 'text' => '已切换到数据库: ' . htmlspecialchars($targetDb)];
    } catch (Exception $e) {
        $message = ['type' => 'error', 'text' => $e->getMessage()];
    }
    $action = 'tables';
}

$execResult = [];
if ($action == 'execute_sql' && isset($_SESSION['db_config']) && $_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        $db = (new DBManager(...array_values($_SESSION['db_config'])))->connect();
        $execResult = $db->executeSql($_POST['sql']);
        $db->close();
    } catch (Exception $e) {
        $message = ['type' => 'error', 'text' => $e->getMessage()];
    }
}

if ($action == 'drop_table' && isset($_SESSION['db_config']) && isset($_GET['table'])) {
    try {
        $db = (new DBManager(...array_values($_SESSION['db_config'])))->connect();
        $table = $_GET['table'];
        if (!DBManager::validateTableName($table)) throw new Exception("非法表名");
        if ($db->dropTable($table)) {
            $message = ['type' => 'success', 'text' => "表 $table 已成功删除"];
        } else {
            $message = ['type' => 'error', 'text' => "删除表失败: " . $db->getConn()->error];
        }
        $db->close();
    } catch (Exception $e) {
        $message = ['type' => 'error', 'text' => $e->getMessage()];
    }
    $action = 'tables';
}

if (in_array($action, ['update_row', 'delete_row', 'insert_row']) && isset($_SESSION['db_config']) && isset($_GET['table'])) {
    try {
        $db = (new DBManager(...array_values($_SESSION['db_config'])))->connect();
        $table = $_GET['table'];
        if (!DBManager::validateTableName($table)) throw new Exception("非法表名");
        $primaryKey = $db->getPrimaryKey($table);
        if (!$primaryKey) {
            throw new Exception("表 $table 没有主键，无法执行此操作");
        }

        if ($action == 'update_row' && $_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['id'])) {
            $id = $_POST['id'];
            unset($_POST['id']);
            if ($db->updateTableRow($table, $_POST, $primaryKey, $id)) {
                $message = ['type' => 'success', 'text' => "数据已成功更新"];
            } else {
                $message = ['type' => 'error', 'text' => "更新失败: " . $db->getConn()->error];
            }
            $action = 'view_table';
        }

        if ($action == 'delete_row' && isset($_GET['id'])) {
            $id = $_GET['id'];
            if ($db->deleteTableRow($table, $primaryKey, $id)) {
                $message = ['type' => 'success', 'text' => "数据已成功删除"];
            } else {
                $message = ['type' => 'error', 'text' => "删除失败: " . $db->getConn()->error];
            }
            $action = 'view_table';
        }

        if ($action == 'insert_row' && $_SERVER['REQUEST_METHOD'] == 'POST') {
            if ($db->insertTableRow($table, $_POST)) {
                $message = ['type' => 'success', 'text' => "数据已成功插入"];
            } else {
                $message = ['type' => 'error', 'text' => "插入失败: " . $db->getConn()->error];
            }
            $action = 'view_table';
        }

        $db->close();
    } catch (Exception $e) {
        $message = ['type' => 'error', 'text' => $e->getMessage()];
        $action = 'view_table';
    }
}

if ($action == 'logout') {
    $_SESSION = [];
    session_unset();
    session_destroy();
    $action = 'login';
    $message = ['type' => 'success', 'text' => '已成功退出登录'];
}

if (in_array($action, ['tables', 'view_table', 'view_structure', 'edit_structure', 'sql']) && isset($_SESSION['db_config'])) {
    try {
        $db = (new DBManager(...array_values($_SESSION['db_config'])))->connect();
    } catch (Exception $e) {
        $message = ['type' => 'error', 'text' => $e->getMessage()];
        $_SESSION = [];
        session_destroy();
        $action = 'login';
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nodeewa-数据库管理工具</title>
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
                <?= htmlspecialchars($message['text']) ?>
            </div>
        <?php endif; ?>

        <?php if ($action == 'login'): ?>
            <div class="max-w-md mx-auto">
                <div class="card p-6">
                    <h2 class="text-2xl font-bold mb-6 text-center text-gray-700">数据库登录</h2>
                    <form method="post" action="?action=login">
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
                            <input type="password" id="pass" name="pass" class="form-input">
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
                        <a href="?action=logout" class="text-danger hover:text-danger/80 flex items-center py-1">
                            <i class="fa fa-sign-out mr-1"></i> 退出登录
                        </a>
                    </div>
                    <div class="text-gray-600 text-sm sm:text-base">
                        当前数据库: <span class="font-medium"><?= htmlspecialchars($_SESSION['db_config']['dbname'] ?? '未选择') ?></span>
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
                                        $dbName = $d['Database'];
                                        $isCurrent = $_SESSION['db_config']['dbname'] == $dbName;
                                    ?>
                                        <tr class="hover:bg-gray-50 <?= $isCurrent ? 'bg-blue-50' : '' ?>">
                                            <td class="py-3 px-4 border-b" data-label="数据库名">
                                                <div class="flex flex-wrap items-center gap-2">
                                                    <?= htmlspecialchars($dbName) ?>
                                                    <?php if (!$isCurrent): ?>
                                                        <a href="?action=change_db&db=<?= urlencode($dbName) ?>" class="btn btn-primary btn-sm">切换</a>
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
                                            $tableName = $t['TableName'];
                                        ?>
                                            <tr class="hover:bg-gray-50">
                                                <td class="py-3 px-4 border-b" data-label="表名"><?= htmlspecialchars($tableName) ?></td>
                                                <td class="py-3 px-4 border-b table-actions">
                                                    <div class="flex flex-wrap gap-2">
                                                        <a href="?action=view_table&table=<?= urlencode($tableName) ?>" class="btn btn-primary">查看数据</a>
                                                        <a href="?action=view_structure&table=<?= urlencode($tableName) ?>" class="btn btn-secondary">表结构</a>
                                                        <button onclick="if(confirm('确定要删除表 <?= htmlspecialchars($tableName) ?> 吗？此操作不可恢复！')) location.href='?action=drop_table&table=<?= urlencode($tableName) ?>'" class="btn btn-danger">删除表</button>
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
                $table = $_GET['table'];
                try {
                    $structure = $db->getTableStructure($table);
                } catch (Exception $e) {
                    $message = ['type' => 'error', 'text' => $e->getMessage()];
                    $structure = [];
                    $action = 'tables';
                }
            ?>
                <?php if ($action != 'tables'): ?>
                <div class="card">
                    <div class="p-4 sm:p-6">
                        <div class="flex flex-wrap justify-between items-center gap-4 mb-4">
                            <h2 class="text-xl font-bold text-gray-700">表结构: <?= htmlspecialchars($table) ?></h2>
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
                                                <td class="py-3 px-4 border-b" data-label="字段"><?= htmlspecialchars($field['Field']) ?></td>
                                                <td class="py-3 px-4 border-b" data-label="类型"><?= htmlspecialchars($field['Type']) ?></td>
                                                <td class="py-3 px-4 border-b" data-label="空"><?= htmlspecialchars($field['Null']) ?></td>
                                                <td class="py-3 px-4 border-b" data-label="键"><?= htmlspecialchars($field['Key']) ?></td>
                                                <td class="py-3 px-4 border-b" data-label="默认"><?= htmlspecialchars($field['Default'] ?? '') ?></td>
                                                <td class="py-3 px-4 border-b" data-label="额外"><?= htmlspecialchars($field['Extra']) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <div>
                            <h3 class="text-lg font-semibold mb-3 text-gray-700">修改表结构 (ALTER TABLE)</h3>
                            <form method="post" action="?action=execute_sql">
                                <input type="hidden" name="redirect" value="view_structure&table=<?= urlencode($table) ?>">
                                <div class="mb-4">
                                    <textarea name="sql" rows="3" class="form-input font-mono text-sm"
                                        placeholder="例如: ALTER TABLE <?= htmlspecialchars($table) ?> ADD COLUMN new_column INT"></textarea>
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
                $table = $_GET['table'];
                try {
                    $primaryKey = $db->getPrimaryKey($table);
                    $structure = $db->getTableStructure($table);
                    $editRow = null;
                    if (isset($_GET['edit']) && $primaryKey) {
                        $editRow = $db->getTableRow($table, $_GET['edit'], $primaryKey);
                    }
                    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
                    $limit = 20;
                    $total = $db->getTableDataCount($table);
                    $totalPages = max(1, ceil($total / $limit));
                    $data = $db->getTableData($table, $page, $limit);
                } catch (Exception $e) {
                    $message = ['type' => 'error', 'text' => $e->getMessage()];
                    $action = 'tables';
                    $data = [];
                }
            ?>
                <?php if ($action != 'tables'): ?>
                <div class="card">
                    <div class="p-4 sm:p-6">
                        <div class="flex flex-wrap justify-between items-center gap-4 mb-6">
                            <h2 class="text-xl font-bold text-gray-700">表数据: <?= htmlspecialchars($table) ?></h2>
                            <div class="flex flex-wrap gap-2">
                                <a href="?action=tables" class="btn btn-outline"><i class="fa fa-arrow-left mr-1"></i>返回列表</a>
                                <a href="?action=view_structure&table=<?= urlencode($table) ?>" class="btn btn-secondary"><i class="fa fa-cogs mr-1"></i>表结构</a>
                                <button onclick="document.getElementById('insertForm').classList.toggle('hidden')" class="btn btn-primary"><i class="fa fa-plus mr-1"></i>添加数据</button>
                            </div>
                        </div>

                        <div id="insertForm" class="mb-6 p-4 bg-gray-50 rounded-lg hidden">
                            <h3 class="text-lg font-semibold mb-3 text-gray-700">添加新记录</h3>
                            <form method="post" action="?action=insert_row&table=<?= urlencode($table) ?>">
                                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                    <?php foreach ($structure as $field):
                                        if (strpos($field['Extra'], 'auto_increment') !== false) continue;
                                    ?>
                                        <div>
                                            <label class="block text-gray-700 mb-1 text-sm" for="insert_<?= htmlspecialchars($field['Field']) ?>">
                                                <?= htmlspecialchars($field['Field']) ?>
                                                <span class="text-gray-500">(<?= htmlspecialchars($field['Type']) ?>)</span>
                                                <?php if ($field['Null'] != 'YES'): ?><span class="text-danger">*</span><?php endif; ?>
                                            </label>
                                            <input type="text" id="insert_<?= htmlspecialchars($field['Field']) ?>" name="<?= htmlspecialchars($field['Field']) ?>" class="form-input" <?= $field['Null'] != 'YES' ? 'required' : '' ?>>
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
                                    <input type="hidden" name="id" value="<?= htmlspecialchars($editRow[$primaryKey]) ?>">
                                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                        <?php foreach ($structure as $field):
                                            $fieldName = $field['Field'];
                                        ?>
                                            <div>
                                                <label class="block text-gray-700 mb-1 text-sm" for="edit_<?= htmlspecialchars($fieldName) ?>">
                                                    <?= htmlspecialchars($fieldName) ?>
                                                    <span class="text-gray-500">(<?= htmlspecialchars($field['Type']) ?>)</span>
                                                    <?php if ($field['Null'] != 'YES'): ?><span class="text-danger">*</span><?php endif; ?>
                                                    <?php if ($fieldName == $primaryKey): ?><span class="text-gray-500 text-xs">(主键不可修改)</span><?php endif; ?>
                                                </label>
                                                <input type="text" id="edit_<?= htmlspecialchars($fieldName) ?>" name="<?= htmlspecialchars($fieldName) ?>"
                                                    value="<?= htmlspecialchars($editRow[$fieldName] ?? '') ?>" class="form-input"
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
                                                    <?= htmlspecialchars($col) ?>
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
                                                <?php foreach ($row as $key => $val): ?>
                                                    <td class="py-3 px-4 border-b" data-label="<?= htmlspecialchars($key) ?>"><?= htmlspecialchars($val ?? '') ?></td>
                                                <?php endforeach; ?>
                                                <td class="py-3 px-4 border-b table-actions">
                                                    <div class="flex flex-wrap gap-1">
                                                        <?php if ($primaryKey): ?>
                                                            <a href="?action=view_table&table=<?= urlencode($table) ?>&page=<?= $page ?>&edit=<?= urlencode($row[$primaryKey]) ?>" class="btn btn-primary btn-sm"><i class="fa fa-edit"></i></a>
                                                            <button onclick="if(confirm('确定要删除这条记录吗？')) location.href='?action=delete_row&table=<?= urlencode($table) ?>&id=<?= urlencode($row[$primaryKey]) ?>&page=<?= $page ?>'" class="btn btn-danger btn-sm"><i class="fa fa-trash"></i></button>
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

            <?php $db->close(); ?>
        <?php endif; ?>
    </div>

    <div id="sqlModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
        <div class="card w-full max-w-5xl max-h-[85vh] flex flex-col mx-2">
            <div class="bg-gray-50 px-4 sm:px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-gray-700">执行SQL语句</h3>
                <button id="closeModal" class="text-gray-500 hover:text-gray-700"><i class="fa fa-times"></i></button>
            </div>
            <div class="p-4 sm:p-6 overflow-y-auto flex-grow">
                <form id="sqlForm" method="post" action="?action=execute_sql">
                    <div class="mb-4">
                        <textarea name="sql" id="sqlInput" rows="8" class="form-input font-mono text-sm"
                            placeholder="输入SQL语句，可执行多条，用分号分隔"><?= htmlspecialchars($_POST['sql'] ?? '') ?></textarea>
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
                        <div class="sql-snippet" data-sql="ALTER TABLE ADD COLUMN " onclick="insertSql(this)">ALTER TABLE</div>
                        <div class="sql-snippet" data-sql="CREATE DATABASE " onclick="insertSql(this)">CREATE DATABASE</div>
                        <div class="sql-snippet" data-sql="DROP DATABASE " onclick="insertSql(this)">DROP DATABASE</div>
                        <div class="sql-snippet" data-sql="CREATE TABLE (id INT PRIMARY KEY AUTO_INCREMENT)" onclick="insertSql(this)">CREATE TABLE</div>
                    </div>
                </div>

                <?php if (!empty($execResult)): ?>
                    <div class="mt-6">
                        <h4 class="text-md font-bold text-gray-700 mb-3">执行结果</h4>
                        <div class="space-y-4">
                            <?php foreach ($execResult as $item): ?>
                                <?php if ($item['type'] == 'error'): ?>
                                    <div class="p-3 bg-red-50 border border-red-200 rounded-md text-red-700"><?= htmlspecialchars($item['message']) ?></div>
                                <?php elseif ($item['type'] == 'info'): ?>
                                    <div class="p-3 bg-blue-50 border border-blue-200 rounded-md text-blue-700"><?= htmlspecialchars($item['message']) ?></div>
                                <?php else: ?>
                                    <div class="overflow-x-auto">
                                        <table class="min-w-full bg-white border border-gray-200 responsive-table">
                                            <thead class="bg-gray-50">
                                                <tr>
                                                    <?php foreach ($item['fields'] as $field): ?>
                                                        <th class="py-2 px-3 border-b text-left text-sm"><?= htmlspecialchars($field) ?></th>
                                                    <?php endforeach; ?>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($item['data'] as $row): ?>
                                                    <tr class="hover:bg-gray-50">
                                                        <?php foreach ($row as $key => $val): ?>
                                                            <td class="py-2 px-3 border-b text-sm" data-label="<?= htmlspecialchars($key) ?>"><?= htmlspecialchars($val ?? '') ?></td>
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
        document.addEventListener('DOMContentLoaded', function() {
            const modal = document.getElementById('sqlModal');
            const sqlBtn = document.getElementById('sqlBtn');
            const closeModal = document.getElementById('closeModal');
            const sqlInput = document.getElementById('sqlInput');
            sqlBtn.addEventListener('click', function() { modal.classList.remove('hidden'); sqlInput.focus(); });
            closeModal.addEventListener('click', function() { modal.classList.add('hidden'); });
            modal.addEventListener('click', function(e) { if (e.target === modal) modal.classList.add('hidden'); });
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && !modal.classList.contains('hidden')) modal.classList.add('hidden');
            });
            <?php if (!empty($execResult)): ?>modal.classList.remove('hidden');<?php endif; ?>
        });

        function insertSql(element) {
            const sql = element.getAttribute('data-sql');
            const input = document.getElementById('sqlInput');
            const start = input.selectionStart;
            const end = input.selectionEnd;
            input.value = input.value.substring(0, start) + sql + input.value.substring(end);
            const newCursorPos = start + sql.length;
            input.focus();
            input.setSelectionRange(newCursorPos, newCursorPos);
        }

        function adjustTableLayout() {
            const tables = document.querySelectorAll('.responsive-table');
            tables.forEach(table => {
                if (window.innerWidth <= 640) table.classList.add('mobile-layout');
                else table.classList.remove('mobile-layout');
            });
        }
        window.addEventListener('resize', adjustTableLayout);
        adjustTableLayout();
    </script>
</body>
</html>

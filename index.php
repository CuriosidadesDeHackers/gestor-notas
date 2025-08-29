<?php


declare(strict_types=1);

/* ---------- Autenticación HTTP Basic ---------- */
function require_basic_auth(string $realm = 'Notas TSD'): void {
    $valid_user = '';
    $valid_pass = '';
    $u = $_SERVER['PHP_AUTH_USER'] ?? null;
    $p = $_SERVER['PHP_AUTH_PW']   ?? null;

    $fail = !$u || !$p || $u !== $valid_user || $p !== $valid_pass;
    if ($fail) {
        header('WWW-Authenticate: Basic realm="'.$realm.'", charset="UTF-8"');
        header('HTTP/1.0 401 Unauthorized');
        echo 'Autenticación requerida.';
        exit;
    }
}
require_basic_auth();

/* ---------- Sesión ---------- */
session_start();

/* ---------- Tema ---------- */
function redirect_self(array $params = []): never {
    $url = strtok($_SERVER['REQUEST_URI'], '?');
    if (!empty($params)) {
        $url .= '?' . http_build_query($params);
    }
    header('Location: ' . $url);
    exit;
}
if (isset($_GET['set_theme'])) {
    $opt = strtolower((string)$_GET['set_theme']);
    $allowed = ['dark','light','auto'];
    if (!in_array($opt, $allowed, true)) $opt = 'auto';
    setcookie('theme', $opt, time() + 365*24*60*60, '/', '', isset($_SERVER['HTTPS']), true);
    $_SESSION['flash'] = ['type' => 'ok', 'msg' => 'Tema cambiado a: ' . $opt];
    redirect_self();
}
$theme = $_COOKIE['theme'] ?? 'auto';
if (!in_array($theme, ['dark','light','auto'], true)) $theme = 'auto';

/* ---------- Configuración DB ---------- */
$dbFile = __DIR__ . DIRECTORY_SEPARATOR . 'notas.db';

try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Crear tabla con nuevos campos
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proyecto TEXT NOT NULL,
            dinero REAL NOT NULL,
            cliente TEXT NOT NULL,
            fecha_entrega TEXT NOT NULL,
            estado TEXT NOT NULL DEFAULT 'en_proceso',
            caracteristicas TEXT DEFAULT '',
            precio_pendiente REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT
        );
    ");
    
    // Añadir nuevos campos si no existen
    $columns = $pdo->query("PRAGMA table_info(notes)")->fetchAll(PDO::FETCH_ASSOC);
    $existing_cols = array_column($columns, 'name');
    
    if (!in_array('estado', $existing_cols)) {
        $pdo->exec("ALTER TABLE notes ADD COLUMN estado TEXT NOT NULL DEFAULT 'en_proceso'");
    }
    if (!in_array('caracteristicas', $existing_cols)) {
        $pdo->exec("ALTER TABLE notes ADD COLUMN caracteristicas TEXT DEFAULT ''");
    }
    if (!in_array('precio_pendiente', $existing_cols)) {
        $pdo->exec("ALTER TABLE notes ADD COLUMN precio_pendiente REAL NOT NULL DEFAULT 0");
    }
    
    // Migrar datos antiguos de "pagado" a "precio_pendiente" si existe
    if (in_array('pagado', $existing_cols) && !in_array('precio_pendiente', $existing_cols)) {
        $pdo->exec("ALTER TABLE notes ADD COLUMN precio_pendiente REAL NOT NULL DEFAULT 0");
        // Si estaba pagado, precio pendiente es 0, si no, precio pendiente es el total
        $pdo->exec("UPDATE notes SET precio_pendiente = CASE WHEN pagado = 1 THEN 0 ELSE dinero END");
        // Eliminar columna antigua (SQLite no soporta DROP COLUMN directamente)
    }
    
    $pdo->exec("
        CREATE INDEX IF NOT EXISTS idx_notes_fecha ON notes(fecha_entrega);
        CREATE INDEX IF NOT EXISTS idx_notes_created_at ON notes(created_at);
        CREATE INDEX IF NOT EXISTS idx_notes_estado ON notes(estado);
        CREATE INDEX IF NOT EXISTS idx_notes_precio_pendiente ON notes(precio_pendiente);
    ");
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Error de conexión con SQLite: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
    exit;
}

/* ---------- CSRF ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
function check_csrf(): void {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        if (!hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
            http_response_code(403);
            exit('Token CSRF inválido.');
        }
    }
}

/* ---------- Helpers ---------- */
function h(?string $s): string {
    return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8');
}
function is_valid_date(string $d): bool {
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $d)) return false;
    [$y,$m,$day] = array_map('intval', explode('-', $d));
    return checkdate($m, $day, $y);
}
function parse_money(string $s): ?float {
    $norm = str_replace([' ', ','], ['', '.'], trim($s));
    if ($norm === '' || !is_numeric($norm)) return null;
    return (float)$norm;
}

$estados_validos = ['en_proceso' => 'En proceso', 'entregado' => 'Entregado', 'esperando_cliente' => 'Esperando cliente'];

/* ---------- Acciones POST ---------- */
$flash = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    check_csrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $proyecto = trim($_POST['proyecto'] ?? '');
        $dinero_s = trim($_POST['dinero'] ?? '');
        $cliente = trim($_POST['cliente'] ?? '');
        $fecha = trim($_POST['fecha_entrega'] ?? '');
        $estado = trim($_POST['estado'] ?? 'en_proceso');
        $caracteristicas = trim($_POST['caracteristicas'] ?? '');
        $precio_pendiente_s = trim($_POST['precio_pendiente'] ?? '0');
        $dinero = parse_money($dinero_s);
        $precio_pendiente = parse_money($precio_pendiente_s);

        if ($proyecto === '' || $cliente === '' || $dinero === null || $precio_pendiente === null || !is_valid_date($fecha) || !array_key_exists($estado, $estados_validos)) {
            $_SESSION['flash'] = ['type' => 'error', 'msg' => 'Campos inválidos. Revisa todos los campos obligatorios.'];
            redirect_self();
        }
        
        $stmt = $pdo->prepare("INSERT INTO notes (proyecto, dinero, cliente, fecha_entrega, estado, caracteristicas, precio_pendiente) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$proyecto, $dinero, $cliente, $fecha, $estado, $caracteristicas, $precio_pendiente]);
        $_SESSION['flash'] = ['type' => 'ok', 'msg' => 'Proyecto creado exitosamente.'];
        redirect_self();
    }

    if ($action === 'update') {
        $id = (int)($_POST['id'] ?? 0);
        $proyecto = trim($_POST['proyecto'] ?? '');
        $dinero_s = trim($_POST['dinero'] ?? '');
        $cliente = trim($_POST['cliente'] ?? '');
        $fecha = trim($_POST['fecha_entrega'] ?? '');
        $estado = trim($_POST['estado'] ?? 'en_proceso');
        $caracteristicas = trim($_POST['caracteristicas'] ?? '');
        $precio_pendiente_s = trim($_POST['precio_pendiente'] ?? '0');
        $dinero = parse_money($dinero_s);
        $precio_pendiente = parse_money($precio_pendiente_s);

        if ($id <= 0 || $proyecto === '' || $cliente === '' || $dinero === null || $precio_pendiente === null || !is_valid_date($fecha) || !array_key_exists($estado, $estados_validos)) {
            $_SESSION['flash'] = ['type' => 'error', 'msg' => 'Campos inválidos. Revisa el formulario.'];
            redirect_self();
        }
        
        $stmt = $pdo->prepare("UPDATE notes SET proyecto=?, dinero=?, cliente=?, fecha_entrega=?, estado=?, caracteristicas=?, precio_pendiente=?, updated_at=datetime('now') WHERE id=?");
        $stmt->execute([$proyecto, $dinero, $cliente, $fecha, $estado, $caracteristicas, $precio_pendiente, $id]);
        $_SESSION['flash'] = ['type' => 'ok', 'msg' => 'Proyecto actualizado exitosamente.'];
        redirect_self();
    }

    if ($action === 'delete') {
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            $stmt = $pdo->prepare("DELETE FROM notes WHERE id=?");
            $stmt->execute([$id]);
            $_SESSION['flash'] = ['type' => 'ok', 'msg' => 'Proyecto eliminado exitosamente.'];
        } else {
            $_SESSION['flash'] = ['type' => 'error', 'msg' => 'ID inválido.'];
        }
        redirect_self();
    }
}

/* ---------- Obtener nota para edición ---------- */
$editId = isset($_GET['edit']) ? (int)$_GET['edit'] : 0;
$editNote = null;
if ($editId > 0) {
    $stmt = $pdo->prepare("SELECT * FROM notes WHERE id=?");
    $stmt->execute([$editId]);
    $editNote = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

/* ---------- Listado y búsqueda ---------- */
$search = trim($_GET['q'] ?? '');
if ($search !== '') {
    $stmt = $pdo->prepare("
        SELECT * FROM notes
        WHERE proyecto LIKE :q OR cliente LIKE :q OR fecha_entrega LIKE :q 
           OR CAST(dinero AS TEXT) LIKE :q OR estado LIKE :q OR caracteristicas LIKE :q
           OR CAST(precio_pendiente AS TEXT) LIKE :q
        ORDER BY date(fecha_entrega) ASC, datetime(created_at) DESC, id DESC
    ");
    $stmt->execute([':q' => "%{$search}%"]);
} else {
    $stmt = $pdo->query("SELECT * FROM notes ORDER BY date(fecha_entrega) ASC, datetime(created_at) DESC, id DESC");
}
$notes = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* ---------- Flash ---------- */
if (isset($_SESSION['flash'])) {
    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);
}
?>
<!doctype html>
<html lang="es" data-theme="<?= h($theme) ?>">
<head>
    <meta charset="utf-8">
    <title>Notas — Sistema de Gestión de Proyectos</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* Variables de diseño profesional */
        :root {
            /* Colores base - tema oscuro */
            --bg-primary: #0a0b0f;
            --bg-secondary: #161922;
            --bg-tertiary: #1f2129;
            --surface: #252834;
            --surface-hover: #2d3142;
            --text-primary: #ffffff;
            --text-secondary: #a3a9b8;
            --text-muted: #6b7280;
            --border: #374151;
            --border-light: #4b5563;
            
            /* Colores de acción */
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --primary-light: rgba(59, 130, 246, 0.1);
            --success: #10b981;
            --success-hover: #059669;
            --success-light: rgba(16, 185, 129, 0.1);
            --warning: #f59e0b;
            --warning-hover: #d97706;
            --warning-light: rgba(245, 158, 11, 0.1);
            --error: #ef4444;
            --error-hover: #dc2626;
            --error-light: rgba(239, 68, 68, 0.1);
            
            /* Estados del proyecto */
            --proceso: #8b5cf6;
            --proceso-light: rgba(139, 92, 246, 0.1);
            --entregado: #10b981;
            --entregado-light: rgba(16, 185, 129, 0.1);
            --esperando: #f59e0b;
            --esperando-light: rgba(245, 158, 11, 0.1);
            
            /* Precio pendiente */
            --pendiente: #f97316;
            --pendiente-light: rgba(249, 115, 22, 0.1);
            --cobrado: #10b981;
            --cobrado-light: rgba(16, 185, 129, 0.1);
            
            /* Sombras */
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.2);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
            --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.4);
            --shadow-xl: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            
            /* Transiciones */
            --transition-fast: 0.15s cubic-bezier(0.4, 0, 0.2, 1);
            --transition: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            --transition-slow: 0.35s cubic-bezier(0.4, 0, 0.2, 1);
            
            /* Espaciado */
            --space-xs: 0.25rem;
            --space-sm: 0.5rem;
            --space: 1rem;
            --space-lg: 1.5rem;
            --space-xl: 2rem;
            --space-2xl: 3rem;
        }

        /* Tema claro */
        html[data-theme="light"] {
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #f1f5f9;
            --surface: #ffffff;
            --surface-hover: #f8fafc;
            --text-primary: #1e293b;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --border-light: #cbd5e1;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            --shadow-md: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 25px 50px -12px rgba(0, 0, 0, 0.2);
        }

        @media (prefers-color-scheme: light) {
            html[data-theme="auto"] {
                --bg-primary: #ffffff;
                --bg-secondary: #f8fafc;
                --bg-tertiary: #f1f5f9;
                --surface: #ffffff;
                --surface-hover: #f8fafc;
                --text-primary: #1e293b;
                --text-secondary: #475569;
                --text-muted: #64748b;
                --border: #e2e8f0;
                --border-light: #cbd5e1;
                --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
                --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                --shadow-md: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
                --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
                --shadow-xl: 0 25px 50px -12px rgba(0, 0, 0, 0.2);
            }
        }

        /* Reset y base */
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 14px;
            transition: background-color var(--transition), color var(--transition);
            min-height: 100vh;
        }

        /* Layout */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: var(--space-xl) var(--space);
        }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            box-shadow: var(--shadow-md);
            overflow: hidden;
        }

        .section {
            padding: var(--space-xl);
        }

        /* Header */
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: var(--space-xl);
            padding: var(--space-lg);
            background: var(--surface);
            border-radius: 16px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow);
            flex-wrap: wrap;
            gap: var(--space);
        }

        .header h1 {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }

        .header-controls {
            display: flex;
            align-items: center;
            gap: var(--space-lg);
            flex-wrap: wrap;
        }

        /* Theme switcher */
        .theme-switch {
            display: flex;
            background: var(--bg-tertiary);
            border-radius: 12px;
            padding: 4px;
            border: 1px solid var(--border);
        }

        .theme-switch a {
            padding: 8px 16px;
            border-radius: 8px;
            text-decoration: none;
            color: var(--text-secondary);
            transition: all var(--transition);
            font-weight: 500;
            font-size: 13px;
        }

        .theme-switch a:hover {
            background: var(--surface-hover);
            color: var(--text-primary);
        }

        .theme-switch a.active {
            background: var(--primary);
            color: white;
            box-shadow: var(--shadow-sm);
        }

        /* Search */
        .search {
            display: flex;
            gap: var(--space-sm);
            align-items: center;
            max-width: 400px;
            flex: 1;
        }

        .search input {
            flex: 1;
            padding: 12px 16px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            transition: all var(--transition);
            font-size: 14px;
        }

        .search input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-light);
            background: var(--surface);
        }

        /* Forms */
        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: var(--space-lg);
            margin-bottom: var(--space-lg);
        }

        .form-field {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
        }

        .form-field.full-width {
            grid-column: 1 / -1;
        }

        label {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        input, select, textarea {
            padding: 14px 16px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            transition: all var(--transition);
            font-family: inherit;
            font-size: 14px;
        }

        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-light);
            background: var(--surface);
        }

        textarea {
            resize: vertical;
            min-height: 120px;
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            gap: var(--space-sm);
            padding: 12px 20px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--surface);
            color: var(--text-primary);
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all var(--transition);
            white-space: nowrap;
        }

        .btn:hover {
            background: var(--surface-hover);
        }

        .btn.primary {
            background: var(--primary);
            border-color: var(--primary);
            color: white;
        }

        .btn.primary:hover {
            background: var(--primary-hover);
        }

        .btn.success {
            background: var(--success);
            border-color: var(--success);
            color: white;
        }

        .btn.success:hover {
            background: var(--success-hover);
        }

        .btn.danger {
            background: var(--error);
            border-color: var(--error);
            color: white;
        }

        .btn.danger:hover {
            background: var(--error-hover);
        }

        .btn.ghost {
            background: transparent;
            border-color: transparent;
        }

        .btn.ghost:hover {
            background: var(--surface-hover);
            border-color: var(--border);
        }

        .btn.small {
            padding: 8px 12px;
            font-size: 12px;
        }

        /* Form actions */
        .form-actions {
            display: flex;
            align-items: center;
            gap: var(--space);
            margin-top: var(--space-lg);
            padding-top: var(--space-lg);
            border-top: 1px solid var(--border);
            flex-wrap: wrap;
        }

        /* Flash messages */
        .flash {
            padding: 16px 20px;
            border-radius: 12px;
            margin-bottom: var(--space-lg);
            display: flex;
            align-items: center;
            gap: var(--space-sm);
            font-weight: 500;
            animation: slideIn var(--transition) ease-out;
        }

        .flash.ok {
            background: var(--success-light);
            border: 1px solid var(--success);
            color: var(--success);
        }

        .flash.error {
            background: var(--error-light);
            border: 1px solid var(--error);
            color: var(--error);
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Table */
        .table-container {
            margin-top: var(--space-xl);
        }

        .table-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: var(--space);
            flex-wrap: wrap;
            gap: var(--space);
        }

        .table-responsive {
            overflow: auto;
            border-radius: 16px;
            border: 1px solid var(--border);
            background: var(--surface);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 1100px;
        }

        th, td {
            padding: 16px 20px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: var(--bg-tertiary);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            position: sticky;
            top: 0;
        }

        tr {
            transition: background-color var(--transition);
        }

        tr:hover {
            background: var(--surface-hover);
        }

        tr:last-child td {
            border-bottom: none;
        }

        /* Status badges */
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-badge.en_proceso {
            background: var(--proceso-light);
            color: var(--proceso);
            border: 1px solid var(--proceso);
        }

        .status-badge.entregado {
            background: var(--entregado-light);
            color: var(--entregado);
            border: 1px solid var(--entregado);
        }

        .status-badge.esperando_cliente {
            background: var(--esperando-light);
            color: var(--esperando);
            border: 1px solid var(--esperando);
        }

        .status-badge::before {
            content: '';
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
        }

        /* Price badges */
        .price-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }

        .price-badge.pendiente {
            background: var(--pendiente-light);
            color: var(--pendiente);
            border: 1px solid var(--pendiente);
        }

        .price-badge.cobrado {
            background: var(--cobrado-light);
            color: var(--cobrado);
            border: 1px solid var(--cobrado);
        }

        /* Actions */
        .actions {
            display: flex;
            gap: var(--space-sm);
            white-space: nowrap;
        }

        .actions .btn {
            padding: 8px 14px;
            font-size: 12px;
        }

        /* Statistics */
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: var(--space);
            margin-bottom: var(--space-xl);
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: var(--space-lg);
            text-align: center;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: var(--space-xs);
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Características link */
        .characteristics-link {
            color: var(--primary);
            cursor: pointer;
            text-decoration: none;
            border: 1px solid var(--primary);
            background: var(--primary-light);
            padding: 4px 8px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 600;
            transition: all var(--transition);
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }

        .characteristics-link:hover {
            background: var(--primary);
            color: white;
        }

        /* Modal styles */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(8px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transition: all var(--transition);
            padding: var(--space);
        }

        .modal-overlay.show {
            opacity: 1;
            visibility: visible;
        }

        .modal {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 20px;
            box-shadow: var(--shadow-xl);
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
            width: 100%;
        }

        .modal-header {
            padding: var(--space-xl);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .modal-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }

        .modal-close {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 1.5rem;
            padding: 8px;
            border-radius: 8px;
            transition: all var(--transition);
        }

        .modal-close:hover {
            background: var(--surface-hover);
            color: var(--text-primary);
        }

        .modal-body {
            padding: var(--space-xl);
        }

        .modal-characteristics {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: var(--space-lg);
            line-height: 1.6;
            color: var(--text-primary);
            white-space: pre-wrap;
            font-size: 14px;
        }

        /* Calendar Styles */
        .calendar-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 20px;
            padding: 30px;
            margin-top: 30px;
            color: white;
            backdrop-filter: blur(10px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }

        .calendar-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }

        .calendar-nav {
            background: rgba(255, 255, 255, 0.2);
            border: none;
            color: white;
            padding: 10px 15px;
            border-radius: 50%;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 18px;
        }

        .calendar-nav:hover {
            background: rgba(255, 255, 255, 0.3);
        }

        .calendar-grid {
            display: grid;
            grid-template-columns: repeat(7, 1fr);
            gap: 10px;
            margin-bottom: 30px;
        }

        .calendar-day-header {
            text-align: center;
            font-weight: bold;
            padding: 10px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            font-size: 14px;
        }

        .calendar-day {
            aspect-ratio: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            font-weight: 500;
        }

        .calendar-day:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        .calendar-day.has-event {
            background: rgba(255, 255, 255, 0.3);
        }

        .calendar-day.has-event::after {
            content: '';
            position: absolute;
            bottom: 3px;
            left: 50%;
            transform: translateX(-50%);
            width: 6px;
            height: 6px;
            background: #ffd700;
            border-radius: 50%;
        }

        .calendar-day.other-month {
            opacity: 0.3;
            cursor: default;
        }

        .calendar-day.today {
            background: rgba(255, 215, 0, 0.3);
            border: 2px solid #ffd700;
        }

        /* Event Modal Styles */
        .event-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
            z-index: 1000;
            animation: fadeIn 0.3s ease;
        }

        .event-modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .event-modal-content {
            background: var(--surface);
            border-radius: 20px;
            padding: 30px;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            border: 1px solid var(--border);
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--text-secondary);
        }

        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid var(--border);
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
            background: var(--bg-secondary);
            color: var(--text-primary);
        }

        .form-group input:focus,
        .form-group textarea:focus,
        .form-group select:focus {
            outline: none;
            border-color: var(--primary);
        }

        .btn-primary {
            background: var(--primary);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            margin-right: 10px;
        }

        .btn-primary:hover {
            background: var(--primary-hover);
        }

        .btn-secondary {
            background: var(--surface);
            color: var(--text-secondary);
            border: 2px solid var(--border);
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn-secondary:hover {
            background: var(--surface-hover);
            border-color: var(--border-light);
        }

        .upcoming-events {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            padding: 20px;
            margin-top: 20px;
        }

        .event-item {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
        }

        .event-date {
            font-weight: bold;
            color: #ffd700;
            font-size: 14px;
        }

        .event-title {
            font-size: 16px;
            margin: 5px 0;
        }

        .event-description {
            font-size: 14px;
            opacity: 0.8;
        }

        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #4CAF50;
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            transform: translateX(400px);
            transition: transform 0.3s ease;
            z-index: 1001;
        }

        .notification.show {
            transform: translateX(0);
        }

        /* Responsive */
        @media (max-width: 1200px) {
            .form-grid {
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: var(--space) var(--space-sm);
            }

            .header {
                flex-direction: column;
                align-items: stretch;
                gap: var(--space-lg);
            }

            .header h1 {
                font-size: 1.5rem;
                text-align: center;
            }

            .header-controls {
                flex-direction: column;
                gap: var(--space);
            }

            .search {
                max-width: 100%;
            }

            .form-grid {
                grid-template-columns: 1fr;
            }

            .form-actions {
                flex-direction: column;
            }

            .btn {
                width: 100%;
                justify-content: center;
            }

            /* Mobile table */
            .table-responsive {
                overflow: visible;
                border: none;
                background: transparent;
            }

            table {
                min-width: 0;
                border-collapse: separate;
                border-spacing: 0 12px;
            }

            thead {
                display: none;
            }

            tr {
                display: block;
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 16px;
                padding: var(--space-lg);
                box-shadow: var(--shadow);
            }

            td {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                padding: 8px 0;
                border-bottom: 1px solid var(--border);
                gap: var(--space);
            }

            td:last-child {
                border-bottom: none;
                justify-content: center;
            }

            td::before {
                content: attr(data-label);
                font-weight: 600;
                color: var(--text-secondary);
                min-width: 120px;
                text-transform: uppercase;
                font-size: 11px;
                letter-spacing: 0.5px;
            }

            .actions {
                flex-direction: column;
                width: 100%;
                gap: var(--space-sm);
            }

            .modal {
                margin: var(--space);
                max-height: 90vh;
            }

            .modal-header {
                padding: var(--space);
            }

            .modal-body {
                padding: var(--space);
            }
        }

        /* Form section styling */
        .form-section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: var(--space-lg);
            padding-bottom: var(--space);
            border-bottom: 1px solid var(--border);
        }

        .form-section-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        /* Money formatting */
        .money {
            font-weight: 600;
            color: var(--success);
        }

        .money.pending {
            color: var(--pendiente);
        }

        /* Footer */
        .footer {
            margin-top: var(--space-2xl);
            padding: var(--space-lg);
            text-align: center;
            color: var(--text-muted);
            font-size: 12px;
            border-top: 1px solid var(--border);
        }

        .footer code {
            background: var(--bg-tertiary);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }

        /* Utilities */
        .nowrap { white-space: nowrap; }
        .text-center { text-align: center; }
        .text-muted { color: var(--text-muted); }
        .font-mono { font-family: 'Courier New', monospace; }

        /* Smooth scrolling */
        html {
            scroll-behavior: smooth;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 Sistema de Gestión de Proyectos</h1>
            <div class="header-controls">
                <form class="search" method="get" action="">
                    <input type="text" name="q" placeholder="Buscar proyectos, clientes, estados..." value="<?= h($search) ?>">
                    <button class="btn primary">🔍 Buscar</button>
                    <?php if ($search !== ''): ?>
                        <a class="btn ghost" href="<?= h(strtok($_SERVER['REQUEST_URI'],'?')) ?>">✖</a>
                    <?php endif; ?>
                </form>
                <div class="theme-switch">
                    <?php
                        $base = h(strtok($_SERVER['REQUEST_URI'],'?'));
                        $qs = function($opt) { return '?set_theme='.urlencode($opt); };
                    ?>
                    <a href="<?= $base . $qs('dark') ?>" class="<?= $theme==='dark'?'active':'' ?>">🌙 Oscuro</a>
                    <a href="<?= $base . $qs('light') ?>" class="<?= $theme==='light'?'active':'' ?>">☀️ Claro</a>
                    <a href="<?= $base . $qs('auto') ?>" class="<?= $theme==='auto'?'active':'' ?>">🔄 Auto</a>
                </div>
            </div>
        </div>

        <?php if (!empty($flash)): ?>
            <div class="flash <?= $flash['type']==='ok' ? 'ok':'error' ?>">
                <?= $flash['type']==='ok' ? '✅' : '❌' ?> <?= h($flash['msg']) ?>
            </div>
        <?php endif; ?>

        <!-- Estadísticas -->
        <?php if (!empty($notes)): ?>
            <?php
                $total_proyectos = count($notes);
                $proyectos_entregados = count(array_filter($notes, fn($n) => $n['estado'] === 'entregado'));
                $total_dinero = array_sum(array_column($notes, 'dinero'));
                $total_pendiente = array_sum(array_column($notes, 'precio_pendiente'));
                $dinero_cobrado = $total_dinero - $total_pendiente;
            ?>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value"><?= $total_proyectos ?></div>
                    <div class="stat-label">Total Proyectos</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value"><?= $proyectos_entregados ?></div>
                    <div class="stat-label">Entregados</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">€<?= number_format($total_dinero, 2, ',', '.') ?></div>
                    <div class="stat-label">Dinero Total</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">€<?= number_format($dinero_cobrado, 2, ',', '.') ?></div>
                    <div class="stat-label">Dinero Cobrado</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">€<?= number_format($total_pendiente, 2, ',', '.') ?></div>
                    <div class="stat-label">Precio Pendiente</div>
                </div>
            </div>
        <?php endif; ?>

        <!-- Formulario -->
        <div class="card section">
            <div class="form-section-header">
                <h2 class="form-section-title">
                    <?= $editNote ? '✏️ Editar Proyecto #'.h((string)$editNote['id']) : '➕ Nuevo Proyecto' ?>
                </h2>
                <?php if ($editNote): ?>
                    <a class="btn ghost" href="<?= h(strtok($_SERVER['REQUEST_URI'],'?')) ?>">➕ Nuevo Proyecto</a>
                <?php endif; ?>
            </div>

            <form method="post" action="">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                <?php if ($editNote): ?>
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="id" value="<?= h((string)$editNote['id']) ?>">
                <?php else: ?>
                    <input type="hidden" name="action" value="create">
                <?php endif; ?>

                <div class="form-grid">
                    <div class="form-field">
                        <label for="proyecto">Nombre del Proyecto</label>
                        <input type="text" id="proyecto" name="proyecto" maxlength="200" value="<?= h($editNote['proyecto'] ?? '') ?>" required placeholder="Ej. Desarrollo web corporativo">
                    </div>

                    <div class="form-field">
                        <label for="dinero">Importe Total (€)</label>
                        <input type="number" id="dinero" name="dinero" step="0.01" inputmode="decimal" value="<?= isset($editNote['dinero']) ? h((string)$editNote['dinero']) : '' ?>" required placeholder="0.00">
                    </div>

                    <div class="form-field">
                        <label for="precio_pendiente">Precio Pendiente (€)</label>
                        <input type="number" id="precio_pendiente" name="precio_pendiente" step="0.01" inputmode="decimal" value="<?= isset($editNote['precio_pendiente']) ? h((string)$editNote['precio_pendiente']) : '0' ?>" placeholder="0.00">
                    </div>

                    <div class="form-field">
                        <label for="cliente">Cliente</label>
                        <input type="text" id="cliente" name="cliente" maxlength="200" value="<?= h($editNote['cliente'] ?? '') ?>" required placeholder="Nombre del cliente">
                    </div>

                    <div class="form-field">
                        <label for="fecha_entrega">Fecha de Entrega</label>
                        <input type="date" id="fecha_entrega" name="fecha_entrega" value="<?= h($editNote['fecha_entrega'] ?? '') ?>" required>
                    </div>

                    <div class="form-field">
                        <label for="estado">Estado del Proyecto</label>
                        <select id="estado" name="estado" required>
                            <?php foreach ($estados_validos as $val => $label): ?>
                                <option value="<?= h($val) ?>" <?= ($editNote['estado'] ?? 'en_proceso') === $val ? 'selected' : '' ?>>
                                    <?= h($label) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="form-field full-width">
                        <label for="caracteristicas">Características y Notas del Proyecto</label>
                        <textarea id="caracteristicas" name="caracteristicas" placeholder="Describe las características del proyecto, notas importantes, tecnologías utilizadas, requisitos específicos, etc."><?= h($editNote['caracteristicas'] ?? '') ?></textarea>
                    </div>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <?= $editNote ? '💾 Guardar Cambios' : '➕ Crear Proyecto' ?>
                    </button>
                    <?php if ($editNote): ?>
                        <a class="btn ghost" href="<?= h(strtok($_SERVER['REQUEST_URI'],'?')) ?>">❌ Cancelar</a>
                    <?php endif; ?>
                    <span class="text-muted">💾 Se guarda automáticamente en notas.db</span>
                </div>
            </form>
        </div>

        <!-- Tabla de proyectos -->
        <div class="card table-container">
            <div class="section">
                <div class="table-header">
                    <h2 class="form-section-title">📊 Lista de Proyectos (<?= count($notes) ?>)</h2>
                    <div class="status-badge en_proceso">📈 Ordenados por fecha de entrega</div>
                </div>

                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Proyecto</th>
                                <th>Importe Total</th>
                                <th>Precio Pendiente</th>
                                <th>Cliente</th>
                                <th>Estado</th>
                                <th>Fecha Entrega</th>
                                <th>Características</th>
                                <th>Creado</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!$notes): ?>
                                <tr>
                                    <td colspan="10" class="text-center text-muted">
                                        📝 No hay proyectos todavía. ¡Crea tu primer proyecto!
                                    </td>
                                </tr>
                            <?php else: foreach ($notes as $n): ?>
                                <tr>
                                    <td data-label="ID" class="nowrap font-mono">#<?= h((string)$n['id']) ?></td>
                                    <td data-label="Proyecto"><strong><?= nl2br(h($n['proyecto'])) ?></strong></td>
                                    <td data-label="Importe Total" class="money">€<?= h(number_format((float)$n['dinero'], 2, ',', '.')) ?></td>
                                    <td data-label="Precio Pendiente">
                                        <?php $pendiente = (float)$n['precio_pendiente']; ?>
                                        <span class="price-badge <?= $pendiente > 0 ? 'pendiente' : 'cobrado' ?>">
                                            <?= $pendiente > 0 ? '⏳ €'.number_format($pendiente, 2, ',', '.') : '✅ Cobrado' ?>
                                        </span>
                                    </td>
                                    <td data-label="Cliente"><?= nl2br(h($n['cliente'])) ?></td>
                                    <td data-label="Estado">
                                        <span class="status-badge <?= h($n['estado']) ?>">
                                            <?= h($estados_validos[$n['estado']] ?? $n['estado']) ?>
                                        </span>
                                    </td>
                                    <td data-label="Fecha Entrega" class="nowrap"><?= h((string)$n['fecha_entrega']) ?></td>
                                    <td data-label="Características">
                                        <?php if (!empty($n['caracteristicas'])): ?>
                                            <button class="characteristics-link" onclick="showModal('<?= h((string)$n['id']) ?>', '<?= h(addslashes($n['proyecto'])) ?>', <?= h(json_encode($n['caracteristicas'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP)) ?>)">
                                                📝 Ver notas
                                            </button>
                                        <?php else: ?>
                                            <span class="text-muted">Sin notas</span>
                                        <?php endif; ?>
                                    </td>
                                    <td data-label="Creado" class="text-muted nowrap"><?= date('d/m/Y', strtotime($n['created_at'])) ?></td>
                                    <td data-label="Acciones" class="actions">
                                        <a class="btn small" href="?edit=<?= h((string)$n['id']) ?>">✏️ Editar</a>
                                        <form method="post" action="" style="display:inline" onsubmit="return confirm('¿Eliminar el proyecto #<?= h((string)$n['id']) ?>: <?= h(addslashes($n['proyecto'])) ?>?');">
                                            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="id" value="<?= h((string)$n['id']) ?>">
                                            <input class="btn danger small" type="submit" value="🗑️ Eliminar">
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>

                <?php if (!empty($notes)): ?>
                    <div class="text-muted" style="margin-top: var(--space-lg); padding-top: var(--space); border-top: 1px solid var(--border);">
                        💡 <strong>Tip:</strong> Usa el buscador para filtrar por proyecto, cliente, estado, características o precios. Click en "📝 Ver notas" para leer las características completas.
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Calendar Section -->
        <div class="calendar-section">
            <div class="calendar-header">
                <h2 style="margin: 0; font-size: 28px; font-weight: 700;">📅 Calendario de Citas</h2>
                <div>
                    <button class="calendar-nav" onclick="changeMonth(-1)">‹</button>
                    <span id="currentMonth" style="margin: 0 20px; font-size: 20px; font-weight: 600;"></span>
                    <button class="calendar-nav" onclick="changeMonth(1)">›</button>
                </div>
            </div>
            
            <div class="calendar-grid" id="calendarGrid">
                <!-- Calendar will be generated by JavaScript -->
            </div>

            <div class="upcoming-events">
                <h3 style="margin-top: 0; color: #ffd700;">Próximas Citas</h3>
                <div id="upcomingEvents">
                    <!-- Events will be populated by JavaScript -->
                </div>
            </div>
        </div>

        <div class="footer">
            🔧 Sistema desarrollado con PHP + SQLite • 🔐 Protegido con HTTP Basic Auth • 🎨 Tema: <?= h($theme) ?> • 💾 Base de datos: <code>notas.db</code>
        </div>
    </div>

    <!-- Modal para características -->
    <div id="characteristicsModal" class="modal-overlay" onclick="closeModal(event)">
        <div class="modal" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h3 class="modal-title">
                    📝 <span id="modalProjectName">Características del Proyecto</span>
                </h3>
                <button class="modal-close" onclick="closeModal()" aria-label="Cerrar modal">✕</button>
            </div>
            <div class="modal-body">
                <div id="modalCharacteristics" class="modal-characteristics">
                    Cargando características...
                </div>
            </div>
        </div>
    </div>

    <!-- Modal for adding events -->
    <div id="eventModal" class="event-modal">
        <div class="event-modal-content">
            <h3 style="margin-top: 0; color: var(--text-primary); font-size: 24px;">Nueva Cita</h3>
            <form id="eventForm">
                <div class="form-group">
                    <label for="eventDate">Fecha:</label>
                    <input type="date" id="eventDate" required>
                </div>
                <div class="form-group">
                    <label for="eventTime">Hora:</label>
                    <input type="time" id="eventTime" required>
                </div>
                <div class="form-group">
                    <label for="eventTitle">Título:</label>
                    <input type="text" id="eventTitle" placeholder="Reunión con cliente..." required>
                </div>
                <div class="form-group">
                    <label for="eventType">Tipo:</label>
                    <select id="eventType" required>
                        <option value="meeting">Reunión</option>
                        <option value="call">Llamada</option>
                        <option value="deadline">Fecha límite</option>
                        <option value="presentation">Presentación</option>
                        <option value="other">Otro</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="eventDescription">Descripción:</label>
                    <textarea id="eventDescription" rows="3" placeholder="Detalles adicionales..."></textarea>
                </div>
                <div style="text-align: right;">
                    <button type="button" class="btn-secondary" onclick="closeEventModal()">Cancelar</button>
                    <button type="submit" class="btn-primary">Guardar Cita</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Notification -->
    <div id="notification" class="notification"></div>

    <script>
        // Modal functionality
        function showModal(id, projectName, characteristics) {
            const modal = document.getElementById('characteristicsModal');
            const title = document.getElementById('modalProjectName');
            const content = document.getElementById('modalCharacteristics');
            
            title.textContent = `${projectName} (#${id})`;
            content.textContent = characteristics || 'No hay características definidas para este proyecto.';
            
            modal.classList.add('show');
            document.body.style.overflow = 'hidden';
        }

        function closeModal(event) {
            if (event && event.target !== event.currentTarget) return;
            
            const modal = document.getElementById('characteristicsModal');
            modal.classList.remove('show');
            document.body.style.overflow = '';
        }

        // Cerrar modal con ESC
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeModal();
                closeEventModal();
            }
        });

        // Auto-resize textarea
        document.querySelectorAll('textarea').forEach(textarea => {
            textarea.addEventListener('input', function() {
                this.style.height = 'auto';
                this.style.height = this.scrollHeight + 'px';
            });
            
            // Initialize height
            if (textarea.value) {
                textarea.style.height = 'auto';
                textarea.style.height = textarea.scrollHeight + 'px';
            }
        });

        // Auto-calculate pending price based on total
        const dineroInput = document.getElementById('dinero');
        const pendienteInput = document.getElementById('precio_pendiente');
        
        if (dineroInput && pendienteInput) {
            dineroInput.addEventListener('input', function() {
                // Si el precio pendiente está vacío o es 0, lo igualamos al importe total
                if (!pendienteInput.value || parseFloat(pendienteInput.value) === 0) {
                    pendienteInput.value = this.value;
                }
            });
        }

        // Calendar functionality
        let currentDate = new Date();
        let events = JSON.parse(localStorage.getItem('calendarEvents') || '[]');

        const monthNames = [
            'Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
            'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'
        ];

        const dayNames = ['Dom', 'Lun', 'Mar', 'Mié', 'Jue', 'Vie', 'Sáb'];

        function generateCalendar() {
            const year = currentDate.getFullYear();
            const month = currentDate.getMonth();
            
            document.getElementById('currentMonth').textContent = 
                `${monthNames[month]} ${year}`;

            const firstDay = new Date(year, month, 1);
            const lastDay = new Date(year, month + 1, 0);
            const startDate = new Date(firstDay);
            startDate.setDate(startDate.getDate() - firstDay.getDay());

            const calendarGrid = document.getElementById('calendarGrid');
            calendarGrid.innerHTML = '';

            // Add day headers
            dayNames.forEach(day => {
                const dayHeader = document.createElement('div');
                dayHeader.className = 'calendar-day-header';
                dayHeader.textContent = day;
                calendarGrid.appendChild(dayHeader);
            });

            // Add calendar days
            for (let i = 0; i < 42; i++) {
                const date = new Date(startDate);
                date.setDate(startDate.getDate() + i);
                
                const dayElement = document.createElement('div');
                dayElement.className = 'calendar-day';
                dayElement.textContent = date.getDate();
                
                if (date.getMonth() !== month) {
                    dayElement.classList.add('other-month');
                }
                
                if (isToday(date)) {
                    dayElement.classList.add('today');
                }
                
                if (hasEvent(date)) {
                    dayElement.classList.add('has-event');
                }
                
                dayElement.addEventListener('click', () => openEventModal(date));
                calendarGrid.appendChild(dayElement);
            }

            updateUpcomingEvents();
        }

        function isToday(date) {
            const today = new Date();
            return date.toDateString() === today.toDateString();
        }

        function hasEvent(date) {
            return events.some(event => {
                const eventDate = new Date(event.date);
                return eventDate.toDateString() === date.toDateString();
            });
        }

        function changeMonth(direction) {
            currentDate.setMonth(currentDate.getMonth() + direction);
            generateCalendar();
        }

        function openEventModal(date) {
            if (date.getMonth() !== currentDate.getMonth()) return;
            
            const modal = document.getElementById('eventModal');
            const dateInput = document.getElementById('eventDate');
            
            dateInput.value = date.toISOString().split('T')[0];
            modal.classList.add('show');
        }

        function closeEventModal() {
            const modal = document.getElementById('eventModal');
            modal.classList.remove('show');
            document.getElementById('eventForm').reset();
        }

        function showNotification(message) {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.classList.add('show');
            
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }

        function updateUpcomingEvents() {
            const upcomingContainer = document.getElementById('upcomingEvents');
            const today = new Date();
            
            const upcomingEvents = events
                .filter(event => new Date(event.date + 'T' + event.time) >= today)
                .sort((a, b) => new Date(a.date + 'T' + a.time) - new Date(b.date + 'T' + b.time))
                .slice(0, 5);

            if (upcomingEvents.length === 0) {
                upcomingContainer.innerHTML = '<p style="opacity: 0.7;">No hay citas próximas</p>';
                return;
            }

            upcomingContainer.innerHTML = upcomingEvents.map(event => {
                const eventDate = new Date(event.date + 'T' + event.time);
                const typeEmojis = {
                    meeting: '🤝',
                    call: '📞',
                    deadline: '⏰',
                    presentation: '📊',
                    other: '📝'
                };
                
                return `
                    <div class="event-item">
                        <div class="event-date">${typeEmojis[event.type]} ${eventDate.toLocaleDateString('es-ES')} - ${event.time}</div>
                        <div class="event-title">${event.title}</div>
                        ${event.description ? `<div class="event-description">${event.description}</div>` : ''}
                    </div>
                `;
            }).join('');
        }

        // Event form submission
        document.getElementById('eventForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const newEvent = {
                id: Date.now(),
                date: document.getElementById('eventDate').value,
                time: document.getElementById('eventTime').value,
                title: document.getElementById('eventTitle').value,
                type: document.getElementById('eventType').value,
                description: document.getElementById('eventDescription').value
            };
            
            events.push(newEvent);
            localStorage.setItem('calendarEvents', JSON.stringify(events));
            
            closeEventModal();
            generateCalendar();
            showNotification('✅ Cita guardada correctamente');
        });

        // Close modal when clicking outside
        document.getElementById('eventModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeEventModal();
            }
        });

        // Initialize calendar
        generateCalendar();
    </script>
</body>
</html>
<?php
session_start();
require 'db.php'; // Database connection

// Function to log user access attempts
function logEvent($conn, $user_id, $action, $status) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $stmt = $conn->prepare("INSERT INTO `audit_logs` (`user_id`, `action`, `status`, `ip_address`) VALUES (?, ?, ?, ?)");
    if ($stmt) {
        $stmt->bind_param("isss", $user_id, $action, $status, $ip);
        $stmt->execute();
        $stmt->close();
    }
}

// Redirect to login if user is not authenticated
if (!isset($_SESSION['user_id'])) {
    logEvent($conn, NULL, "Unauthorized access attempt to restricted page", "failure");
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$page = $_GET['page'] ?? ''; // Get requested page from URL

// Map "page names" to actual permission names in the database
$page_permissions = [
    'manage_users'   => 'manage_users',
    'manage_orders'  => 'manage_orders',
    'reports'        => 'view_reports',
    'audit_logs'     => 'view_audit_logs',
    'settings'       => 'access_settings'
];

// Check if the requested page maps to a valid permission
if (!isset($page_permissions[$page])) {
    logEvent($conn, $user_id, "Attempted access to non-existent page: $page", "error");
    header("Location: 403.php");
    exit();
}

// Get the required permission for the requested page
$required_permission = $page_permissions[$page];

// Check if the user has this permission
if (!in_array($required_permission, $_SESSION['permissions'])) {
    logEvent($conn, $user_id, "Unauthorized attempt to access $page", "failure");
    header("Location: 403.php");
    exit();
}

// Log successful access
logEvent($conn, $user_id, "Accessed $page", "success");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GateKeeper - Access Granted</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="height: 100vh;">
    <div class="container text-center">
        <h1 class="text-success"><i class="bi bi-check-circle-fill"></i> Access Granted</h1>
        <p class="lead">You have access to <strong><?php echo htmlspecialchars(ucwords(str_replace('_', ' ', $page))); ?></strong>, but this resource is not implemented in this demo.</p>
        <a href="dashboard.php" class="btn btn-primary mt-3"><i class="bi bi-arrow-left"></i> Back to Dashboard</a>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

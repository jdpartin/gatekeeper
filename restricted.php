<?php
session_start();
require 'db.php'; // Database connection

// Redirect to login if user is not authenticated
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_role = $_SESSION['role']; // User role from session
$page = $_GET['page'] ?? ''; // Get requested page from URL

// Define which roles can access which pages
$permissions = [
    'manage_users'   => ['admin'],
    'manage_orders'  => ['admin', 'manager'],
    'reports'        => ['admin', 'manager', 'employee'],
    'audit_logs'     => ['admin'],
    'settings'       => ['admin']
];

// Check if the page exists and if the user has permission
if (!isset($permissions[$page]) || !in_array($user_role, $permissions[$page])) {
    header("Location: 403.php");
    exit();
}
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

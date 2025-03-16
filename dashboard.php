<?php
session_start();
require 'db.php'; // Database connection

// Redirect to login if user is not authenticated
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Get user details
$user_email = $_SESSION['email'];
$user_role = $_SESSION['role']; // This should be stored as a string (admin, manager, employee, viewer)
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GateKeeper - Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">GateKeeper</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="account.php">Account</a></li>
                    <li class="nav-item"><a class="nav-link text-danger" href="logout.php">Logout</a></li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-5">
        <h1 class="text-center">Welcome, <?php echo htmlspecialchars($user_email); ?>!</h1>
        <p class="text-center text-muted">Your role: <strong><?php echo strtoupper($user_role); ?></strong></p>

        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="list-group">
                    <a href="reports.php" class="list-group-item list-group-item-action">
                        <i class="bi bi-bar-chart-fill"></i> View Reports
                    </a>

                    <?php if ($user_role == 'admin' || $user_role == 'manager'): ?>
                        <a href="manage_orders.php" class="list-group-item list-group-item-action">
                            <i class="bi bi-box-seam"></i> Manage Orders
                        </a>
                    <?php endif; ?>

                    <?php if ($user_role == 'admin'): ?>
                        <a href="manage_users.php" class="list-group-item list-group-item-action">
                            <i class="bi bi-people-fill"></i> Manage Users
                        </a>
                        <a href="audit_logs.php" class="list-group-item list-group-item-action">
                            <i class="bi bi-shield-lock"></i> View Audit Logs
                        </a>
                        <a href="settings.php" class="list-group-item list-group-item-action">
                            <i class="bi bi-gear-fill"></i> System Settings
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

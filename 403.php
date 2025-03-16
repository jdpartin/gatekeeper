<?php
session_start();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>403 - Access Denied</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="height: 100vh;">
    <div class="container text-center">
        <h1 class="display-3 text-danger"><i class="bi bi-x-circle-fill"></i> 403</h1>
        <h2 class="text-dark">Access Denied</h2>
        <p class="lead text-muted">You do not have permission to access this page.</p>

        <?php if (isset($_SESSION['user_id'])): ?>
            <a href="dashboard.php" class="btn btn-primary"><i class="bi bi-arrow-left"></i> Go to Dashboard</a>
        <?php else: ?>
            <a href="login.php" class="btn btn-primary"><i class="bi bi-box-arrow-in-right"></i> Login</a>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

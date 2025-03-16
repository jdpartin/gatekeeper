<?php
session_start();
require 'db.php'; // Database connection

// Function to log events
function logEvent($conn, $user_id, $action, $status) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $stmt = $conn->prepare("INSERT INTO `audit_logs` (`user_id`, `action`, `status`, `ip_address`) VALUES (?, ?, ?, ?)");
    if ($stmt) {
        $stmt->bind_param("isss", $user_id, $action, $status, $ip);
        $stmt->execute();
        $stmt->close();
    }
}

// Check if user is authenticated
if (!isset($_SESSION['user_id'])) {
    logEvent($conn, NULL, "Unauthorized attempt to access Audit Logs", "failure");
    header("Location: login.php");
    exit();
}

// Check if user has permission
if (!in_array('view_audit_logs', $_SESSION['permissions'])) {
    logEvent($conn, $_SESSION['user_id'], "Attempted unauthorized access to Audit Logs", "failure");
    header("Location: 403.php");
    exit();
}

// Log successful access
logEvent($conn, $_SESSION['user_id'], "Accessed Audit Logs", "success");

// Fetch audit logs from the database
$stmt = $conn->prepare("SELECT user_id, action, status, ip_address, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 50");
$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GateKeeper - View Audit Logs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <h1 class="text-center">Audit Logs</h1>
        <table class="table table-bordered table-striped mt-4">
            <thead class="table-dark">
                <tr>
                    <th>User ID</th>
                    <th>Action</th>
                    <th>Status</th>
                    <th>IP Address</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = $result->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($row['user_id']); ?></td>
                        <td><?php echo htmlspecialchars($row['action']); ?></td>
                        <td><?php echo htmlspecialchars($row['status']); ?></td>
                        <td><?php echo htmlspecialchars($row['ip_address']); ?></td>
                        <td><?php echo htmlspecialchars($row['timestamp']); ?></td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
        <a href="dashboard.php" class="btn btn-primary">Back to Dashboard</a>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>

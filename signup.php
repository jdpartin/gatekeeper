<?php
session_start();
require 'db.php'; // Include database connection

$error_message = "";
$success_message = "";

// Function to log system errors
function logError($conn, $message) {
    $ip = $_SERVER['REMOTE_ADDR']; // Capture IP address
    $stmt = $conn->prepare("INSERT INTO `audit_logs` (`user_id`, `action`, `status`, `ip_address`) VALUES (NULL, ?, 'error', ?)");
    if ($stmt) {
        $stmt->bind_param("ss", $message, $ip);
        $stmt->execute();
        $stmt->close();
    }
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $role_id = $_POST['role_id'];

    // Validate input
    if (!empty($email) && !empty($password) && !empty($role_id)) {
        // Check if email already exists
        $stmt = $conn->prepare("SELECT `id` FROM `users` WHERE `email` = ?");
        if (!$stmt) {
            logError($conn, "Database error in SELECT: " . $conn->error);
            $error_message = "An unexpected error occurred. Please try again later.";
        } else {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $error_message = "Email is already registered.";
            } else {
                // Hash the password
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                // Insert new user into database
                $stmt = $conn->prepare("INSERT INTO `users` (`email`, `password`, `role_id`) VALUES (?, ?, ?)");
                if (!$stmt) {
                    logError($conn, "Database error in INSERT: " . $conn->error);
                    $error_message = "An unexpected error occurred. Please try again later.";
                } else {
                    $stmt->bind_param("ssi", $email, $hashed_password, $role_id);

                    if ($stmt->execute()) {
                        $success_message = "Account created successfully! You can now <a href='login.php'>log in</a>.";
                    } else {
                        logError($conn, "Failed to execute INSERT: " . $stmt->error);
                        $error_message = "Error creating account. Please try again.";
                    }

                    $stmt->close();
                }
            }
            $stmt->close();
        }
    } else {
        $error_message = "All fields are required.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GateKeeper - Sign Up</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="height: 100vh;">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h2 class="text-center">Sign Up for GateKeeper</h2>

                        <?php if (!empty($error_message)): ?>
                            <div class="alert alert-danger text-center">
                                <?php echo $error_message; ?>
                            </div>
                        <?php endif; ?>

                        <?php if (!empty($success_message)): ?>
                            <div class="alert alert-success text-center">
                                <?php echo $success_message; ?>
                            </div>
                        <?php endif; ?>

                        <form action="signup.php" method="POST">
                            <div class="mb-3">
                                <label for="email" class="form-label">Email Address</label>
                                <input type="email" name="email" class="form-control" required>
                            </div>

                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" name="password" class="form-control" required>
                            </div>

                            <div class="mb-3">
                                <label for="role_id" class="form-label">Select Role</label>
                                <select name="role_id" class="form-select" required>
                                    <option value="3">Employee</option> <!-- Default role -->
                                    <option value="2">Manager</option>
                                    <option value="1">Admin</option>
                                </select>
                            </div>

                            <button type="submit" class="btn btn-primary w-100">Sign Up</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
